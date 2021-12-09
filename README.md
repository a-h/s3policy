# s3policy

Applies S3 policies and settings which pass AWS Config's default settings.

## Installation

```bash
go install github.com/a-h/s3policy@latest
```

## Usage

```bash
s3policy -bucket=name-of-bucket -deleteOldVersions=true -deleteAfterDays=30 -logToBucket=logging-bucket-name -version=true
```
