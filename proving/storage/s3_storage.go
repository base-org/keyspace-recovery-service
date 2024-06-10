package storage

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type S3Storage struct {
	client *s3.Client
	bucket string
}

func NewS3Storage(bucket string) (Storage, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion("us-east-1"))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %w", err)
	}
	return &S3Storage{
		client: s3.NewFromConfig(cfg),
		bucket: bucket,
	}, nil
}

func (s S3Storage) Reader(key string) (io.ReadCloser, error) {
	attributes, err := s.client.GetObjectAttributes(context.TODO(), &s3.GetObjectAttributesInput{
		Bucket:           &s.bucket,
		Key:              &key,
		ObjectAttributes: []types.ObjectAttributes{types.ObjectAttributesObjectSize},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to get object attributes: %w", err)
	}

	object, err := s.client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: &s.bucket,
		Key:    &key,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to get object: %w", err)
	}
	return NewLoggingReader(object.Body, "Downloading", key, *attributes.ObjectSize), nil
}

func (s S3Storage) Writer(key string) (io.WriteCloser, error) {
	uploader := manager.NewUploader(s.client)

	reader, writer := io.Pipe()
	w := &writeWaiter{WriteCloser: writer}
	w.wg.Add(1)
	go func() {
		_, err := uploader.Upload(context.TODO(), &s3.PutObjectInput{
			Bucket: &s.bucket,
			Key:    &key,
			Body:   reader,
		})
		w.wg.Done()
		if err != nil {
			_ = reader.CloseWithError(err)
		}
	}()

	return w, nil
}

type writeWaiter struct {
	io.WriteCloser
	wg sync.WaitGroup
}

func (w *writeWaiter) Close() error {
	err := w.WriteCloser.Close()
	if err != nil {
		return err
	}
	w.wg.Wait()
	return nil
}
