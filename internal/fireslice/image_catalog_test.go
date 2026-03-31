package fireslice

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileImageStoreDefaultsAndCRUD(t *testing.T) {
	dir := t.TempDir()
	store := NewFileImageStore(filepath.Join(dir, "catalog.json"))

	images, err := store.ListImages(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(images) == 0 || images[0].Ref != "ussyuntu" {
		t.Fatalf("default images = %#v", images)
	}

	if err := store.AddImage(context.Background(), ImageCatalogEntry{Name: "Debian 12", Ref: "ghcr.io/example/debian:12", Description: "Stable base image"}); err != nil {
		t.Fatal(err)
	}
	images, err = store.ListImages(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(images) != 1 || images[0].Ref != "ghcr.io/example/debian:12" {
		t.Fatalf("stored images = %#v", images)
	}
	if _, err := os.Stat(filepath.Join(dir, "catalog.json")); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteImage(context.Background(), "ghcr.io/example/debian:12"); err != nil {
		t.Fatal(err)
	}
	images, err = store.ListImages(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(images) != 1 || images[0].Ref != "ussyuntu" {
		t.Fatalf("images after delete = %#v", images)
	}
}
