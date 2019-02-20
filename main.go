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
var encryptFlag = flag.Bool("encrypt", true, "encrypt the bucket")
var versionFlag = flag.Bool("version", true, "version the bucket")
var sslOnlyFlag = flag.Bool("sslOnly", true, "limit bucket access to SSL")
var logToBucketNameFlag = flag.String("logToBucket", "", "bucket to send logs to")
var bucketFlag = flag.String("bucket", "", "the name of the bucket to process")
var allBucketsFlag = flag.Bool("allBuckets", false, "set to true to process all buckets")

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

	err := update(ctx, *allBucketsFlag, *bucketFlag, *regionFlag)
	if err != nil {
		os.Stderr.WriteString(err.Error())
		os.Exit(-1)
	}
}

func update(ctx context.Context, allBuckets bool, bucketName string, region string) (err error) {
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
	for _, b := range buckets {
		select {
		case <-ctx.Done():
			return nil
		default:
			err = applyRules(ctx, client, &b, logToBucketNameFlag, *encryptFlag, *versionFlag, *sslOnlyFlag)
			if err != nil {
				return fmt.Errorf("%s: failed to apply rules: %v", b, err)
			}
			fmt.Printf("%s: OK\n", b)
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

func applyRules(ctx context.Context, client *s3.S3, name *string, logToBucketName *string, encrypt, version, sslOnly bool) error {
	loc, err := client.GetBucketLocationWithContext(ctx, &s3.GetBucketLocationInput{
		Bucket: name,
	})
	if err != nil {
		return fmt.Errorf("%s: failed to get bucket location: %v", *name, err)
	}
	if loc.LocationConstraint == nil {
		// Skip, the bucket doesn't actually exist.
		return nil
	}
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(*loc.LocationConstraint),
	})
	if err != nil {
		return fmt.Errorf("%s: failed to create local session: %v", *name, err)
	}
	localClient := s3.New(sess)
	var ok bool
	if encrypt {
		fmt.Printf("%s: encrypting....\n", *name)
		ok, err = encryptBucket(ctx, localClient, name)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Printf("%s:   - already encrypted\n", *name)
		}
	}
	if version {
		fmt.Printf("%s: versioning...\n", *name)
		ok, err = versionBucket(ctx, localClient, name)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Printf("%s:   - versioning already enabled\n", *name)
		}
	}
	if sslOnly {
		fmt.Printf("%s: disabling non-SSL access...\n", *name)
		ok, err = disableNonSSL(ctx, localClient, name)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Printf("%s:   - a policy is already set on the bucket\n", *name)
		}
	}
	if logToBucketName != nil && *logToBucketName != "" {
		fmt.Printf("%s: enabling logging to %s...\n", *name, *logToBucketName)
		ok, err = enableLogging(ctx, localClient, name, logToBucketName)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Printf("%s:   - already has logging enabled\n", *name)
		}
	}

	return nil
}

func enableLogging(ctx context.Context, client *s3.S3, name, logToBucketName *string) (ok bool, err error) {
	resp, err := client.GetBucketLoggingWithContext(ctx, &s3.GetBucketLoggingInput{
		Bucket: name,
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
		Bucket: name,
		BucketLoggingStatus: &s3.BucketLoggingStatus{
			LoggingEnabled: &s3.LoggingEnabled{
				TargetBucket: logToBucketName,
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

func encryptBucket(ctx context.Context, client *s3.S3, name *string) (ok bool, err error) {
	resp, err := client.GetBucketEncryptionWithContext(ctx, &s3.GetBucketEncryptionInput{
		Bucket: name,
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
		Bucket: name,
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

func versionBucket(ctx context.Context, client *s3.S3, name *string) (ok bool, err error) {
	resp, err := client.GetBucketVersioningWithContext(ctx, &s3.GetBucketVersioningInput{
		Bucket: name,
	})
	if err != nil {
		err = fmt.Errorf("failed to get bucket versioning: %v", err)
		return
	}
	if resp.Status != nil && *resp.Status == s3.BucketVersioningStatusEnabled {
		return
	}
	_, err = client.PutBucketVersioningWithContext(ctx, &s3.PutBucketVersioningInput{
		Bucket: name,
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

func disableNonSSL(ctx context.Context, client *s3.S3, name *string) (ok bool, err error) {
	bp, err := client.GetBucketPolicyWithContext(ctx, &s3.GetBucketPolicyInput{
		Bucket: name,
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
	escName, err := json.Marshal(*name)
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
		Bucket: name,
		Policy: policy,
	})
	if err != nil {
		err = fmt.Errorf("failed to put the bucket policy: %v", err)
		return
	}
	ok = true
	return false, nil
}
