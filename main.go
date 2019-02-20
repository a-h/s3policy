package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/aws/aws-sdk-go/aws/awserr"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

var regionFlag = flag.String("region", "eu-west-2", "The AWS region to target.")
var allBucketsFlag = flag.Bool("allBuckets", false, "set to true to process all buckets")
var bucketFlag = flag.String("bucket", "", "the name of the bucket to process")

var encryptFlag = flag.Bool("encrypt", true, "encrypt the bucket")
var versionFlag = flag.Bool("version", false, "version the bucket")
var sslOnlyFlag = flag.Bool("sslOnly", true, "limit bucket access to SSL")

var logToBucketNameFlag = flag.String("logToBucket", "", "bucket to send logs to")

var deleteOldVersionsFlag = flag.Bool("deleteOldVersions", false, "delete old versions automatically after a period")
var deleteAfterDays = flag.Int("deleteAfterDays", 0, "the number of days after which to delete expired versions")

func main() {
	flag.Parse()

	sigs := make(chan os.Signal)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-sigs
		log.Printf("Shutting down...\n")
		cancel()
	}()

	err := updateWithFlags(ctx)
	if err != nil {
		os.Stderr.WriteString(err.Error())
		os.Exit(-1)
	}
}

func updateWithFlags(ctx context.Context) (err error) {
	region := *regionFlag
	if region == "" {
		return fmt.Errorf("missing region flag")
	}
	if *deleteOldVersionsFlag && *deleteAfterDays <= 0 {
		return fmt.Errorf("invalid -deleteAfterDays flag value")
	}
	return update(ctx, region, *allBucketsFlag, *bucketFlag, *encryptFlag, *versionFlag, *sslOnlyFlag,
		*logToBucketNameFlag, *deleteOldVersionsFlag, *deleteAfterDays)
}

func update(ctx context.Context, region string, allBuckets bool, bucketName string,
	encrypt, version, sslOnly bool,
	logToBucketName string,
	deleteOldVersions bool, deleteAfterDays int) (err error) {
	conf := aws.NewConfig().WithRegion(region)
	sess, err := session.NewSession(conf)
	if err != nil {
		return
	}
	client := s3.New(sess)
	lbr, err := client.ListBucketsWithContext(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return fmt.Errorf("failed to list buckets: %v", err)
	}
	buckets := []string{}
	if allBuckets {
		buckets = append(buckets, getBucketNames(lbr)...)
	}
	if bucketName != "" {
		buckets = append(buckets, bucketName)
	}
	for _, bucketName := range buckets {
		select {
		case <-ctx.Done():
			return nil
		default:
			err = applyRules(ctx, client, bucketName, logToBucketName, encrypt, version, sslOnly,
				deleteOldVersions, deleteAfterDays)
			if err != nil {
				return fmt.Errorf("%s: failed to apply rules: %v", bucketName, err)
			}
			fmt.Printf("%s: OK\n", bucketName)
		}
	}
	return nil
}

func getBucketNames(lbo *s3.ListBucketsOutput) (buckets []string) {
	for _, b := range lbo.Buckets {
		buckets = append(buckets, *b.Name)
	}
	return
}

func applyRules(ctx context.Context, client *s3.S3, name string, logToBucketName string, encrypt, version, sslOnly, deleteOldVersions bool, deleteAfterDays int) error {
	loc, err := client.GetBucketLocationWithContext(ctx, &s3.GetBucketLocationInput{
		Bucket: aws.String(name),
	})
	if err != nil {
		return fmt.Errorf("%s: failed to get bucket location: %v", name, err)
	}
	if loc.LocationConstraint == nil {
		// Skip, the bucket doesn't actually exist.
		return nil
	}
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(*loc.LocationConstraint),
	})
	if err != nil {
		return fmt.Errorf("%s: failed to create local session: %v", name, err)
	}
	localClient := s3.New(sess)
	var ok bool
	if encrypt {
		fmt.Printf("%s: encrypting....\n", name)
		ok, err = encryptBucket(ctx, localClient, name)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Printf("%s:   - already encrypted\n", name)
		}
	}
	if version {
		fmt.Printf("%s: versioning...\n", name)
		ok, err = versionBucket(ctx, localClient, name)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Printf("%s:   - versioning already enabled\n", name)
		}
	}
	if sslOnly {
		fmt.Printf("%s: disabling non-SSL access...\n", name)
		ok, err = disableNonSSL(ctx, localClient, name)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Printf("%s:   - a policy is already set on the bucket\n", name)
		}
	}
	if logToBucketName != "" {
		fmt.Printf("%s: enabling logging to %s...\n", name, logToBucketName)
		ok, err = enableLogging(ctx, localClient, name, logToBucketName)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Printf("%s:   - already has logging enabled\n", name)
		}
	}
	if deleteOldVersions && deleteAfterDays > 0 {
		fmt.Printf("%s: deleting old versions after %d days...\n", name, deleteAfterDays)
		ok, err = deleteOldVersionsAfter(ctx, localClient, name, deleteAfterDays)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Printf("%s:   - already has a lifecycle policy\n", name)
		}
	}

	return nil
}

func deleteOldVersionsAfter(ctx context.Context, client *s3.S3, name string, days int) (ok bool, err error) {
	resp, err := client.GetBucketLifecycleConfigurationWithContext(ctx, &s3.GetBucketLifecycleConfigurationInput{
		Bucket: aws.String(name),
	})
	if err != nil {
		awsErr, isAWSErr := err.(awserr.Error)
		if !isAWSErr || awsErr.Code() != "NoSuchLifecycleConfiguration" {
			err = fmt.Errorf("failed to get lifecycle configuration: %v", err)
			return
		}
	}
	if len(resp.Rules) > 0 {
		return
	}
	_, err = client.PutBucketLifecycleConfigurationWithContext(ctx, &s3.PutBucketLifecycleConfigurationInput{
		Bucket: aws.String(name),
		LifecycleConfiguration: &s3.BucketLifecycleConfiguration{
			Rules: []*s3.LifecycleRule{
				&s3.LifecycleRule{
					ID: aws.String("s3policyRemoveExpired"),
					NoncurrentVersionExpiration: &s3.NoncurrentVersionExpiration{
						NoncurrentDays: aws.Int64(int64(days)),
					},
					Filter:      &s3.LifecycleRuleFilter{},
					Transitions: []*s3.Transition{},
					Status:      aws.String(s3.ExpirationStatusEnabled),
				},
			},
		},
	})
	if err != nil {
		err = fmt.Errorf("failed to put bucket lifecycle: %v", err)
		return
	}
	ok = true
	return
}

func enableLogging(ctx context.Context, client *s3.S3, name, logToBucketName string) (ok bool, err error) {
	resp, err := client.GetBucketLoggingWithContext(ctx, &s3.GetBucketLoggingInput{
		Bucket: aws.String(name),
	})
	if err != nil {
		if awsErr := err.(awserr.Error); awsErr.Code() != "ServerSideEncryptionConfigurationNotFoundError" {
			err = fmt.Errorf("failed to get logging details: %v", err)
			return
		}
	}
	if resp.LoggingEnabled != nil {
		return
	}
	_, err = client.PutBucketLoggingWithContext(ctx, &s3.PutBucketLoggingInput{
		Bucket: aws.String(name),
		BucketLoggingStatus: &s3.BucketLoggingStatus{
			LoggingEnabled: &s3.LoggingEnabled{
				TargetBucket: aws.String(logToBucketName),
				TargetPrefix: aws.String("s3logs/"),
			},
		},
	})
	if err != nil {
		err = fmt.Errorf("failed to apply logging: %v", err)
		return
	}
	ok = true
	return
}

func encryptBucket(ctx context.Context, client *s3.S3, name string) (ok bool, err error) {
	resp, err := client.GetBucketEncryptionWithContext(ctx, &s3.GetBucketEncryptionInput{
		Bucket: aws.String(name),
	})
	if err != nil {
		if awsErr := err.(awserr.Error); awsErr.Code() != "ServerSideEncryptionConfigurationNotFoundError" {
			err = fmt.Errorf("failed to get bucket encryption: %v", err)
			return
		}
	}
	if resp.ServerSideEncryptionConfiguration != nil {
		return
	}
	_, err = client.PutBucketEncryptionWithContext(ctx, &s3.PutBucketEncryptionInput{
		Bucket: aws.String(name),
		ServerSideEncryptionConfiguration: &s3.ServerSideEncryptionConfiguration{
			Rules: []*s3.ServerSideEncryptionRule{
				&s3.ServerSideEncryptionRule{
					ApplyServerSideEncryptionByDefault: &s3.ServerSideEncryptionByDefault{
						SSEAlgorithm: aws.String(s3.ServerSideEncryptionAes256),
					},
				},
			},
		},
	})
	if err != nil {
		err = fmt.Errorf("failed to apply server-side encryption: %v", err)
		return
	}
	ok = true
	return
}

func versionBucket(ctx context.Context, client *s3.S3, name string) (ok bool, err error) {
	resp, err := client.GetBucketVersioningWithContext(ctx, &s3.GetBucketVersioningInput{
		Bucket: aws.String(name),
	})
	if err != nil {
		err = fmt.Errorf("failed to get bucket versioning: %v", err)
		return
	}
	if resp.Status != nil && *resp.Status == s3.BucketVersioningStatusEnabled {
		return
	}
	_, err = client.PutBucketVersioningWithContext(ctx, &s3.PutBucketVersioningInput{
		Bucket: aws.String(name),
		VersioningConfiguration: &s3.VersioningConfiguration{
			Status: aws.String(s3.BucketVersioningStatusEnabled),
		},
	})
	if err != nil {
		err = fmt.Errorf("failed to apply versioning: %v", err)
		return
	}
	ok = true
	return
}

func disableNonSSL(ctx context.Context, client *s3.S3, name string) (ok bool, err error) {
	bp, err := client.GetBucketPolicyWithContext(ctx, &s3.GetBucketPolicyInput{
		Bucket: aws.String(name),
	})
	if err != nil {
		awsErr, isAWSErr := err.(awserr.Error)
		if !isAWSErr || awsErr.Code() != "NoSuchBucketPolicy" {
			err = fmt.Errorf("failed to get bucket policy: %v", err)
			return
		}
	}
	if bp.Policy != nil {
		return
	}
	escName, err := json.Marshal(name)
	if err != nil {
		err = fmt.Errorf("failed to JSON format name")
		return
	}
	policy := aws.String(fmt.Sprintf(`{
		"Statement":[
				{
					"Effect":"Deny",
					"Principal": "*",
						"Action": "*",
						"Resource":"arn:aws:s3:::%s/*",
						"Condition":{
								"Bool": { "aws:SecureTransport": false }
						}
				}
		]
}`, strings.Trim(string(escName), `"`)))
	_, err = client.PutBucketPolicyWithContext(ctx, &s3.PutBucketPolicyInput{
		Bucket: aws.String(name),
		Policy: policy,
	})
	if err != nil {
		err = fmt.Errorf("failed to put the bucket policy: %v", err)
		return
	}
	ok = true
	return false, nil
}
