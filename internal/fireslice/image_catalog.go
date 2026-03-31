package fireslice

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type FileImageStore struct {
	path string
	mu   sync.Mutex
}

func NewFileImageStore(path string) *FileImageStore {
	return &FileImageStore{path: path}
}

func DefaultImages() []ImageCatalogEntry {
	return []ImageCatalogEntry{{
		Name:        "ussyuntu",
		Ref:         "ussyuntu",
		Description: "Local default guest image",
	}}
}

func (s *FileImageStore) ListImages(context.Context) ([]ImageCatalogEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	images, err := s.load()
	if err != nil {
		return nil, err
	}
	if len(images) == 0 {
		images = DefaultImages()
	}
	sort.Slice(images, func(i, j int) bool {
		if images[i].Name == images[j].Name {
			return images[i].Ref < images[j].Ref
		}
		return images[i].Name < images[j].Name
	})
	return images, nil
}

func (s *FileImageStore) AddImage(_ context.Context, image ImageCatalogEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	image.Name = strings.TrimSpace(image.Name)
	image.Ref = strings.TrimSpace(image.Ref)
	image.Description = strings.TrimSpace(image.Description)
	if image.Ref == "" {
		return fmt.Errorf("image reference is required")
	}
	if image.Name == "" {
		image.Name = image.Ref
	}
	images, err := s.load()
	if err != nil {
		return err
	}
	for _, existing := range images {
		if existing.Ref == image.Ref {
			return fmt.Errorf("image already exists")
		}
	}
	images = append(images, image)
	return s.save(images)
}

func (s *FileImageStore) DeleteImage(_ context.Context, ref string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return fmt.Errorf("image reference is required")
	}
	images, err := s.load()
	if err != nil {
		return err
	}
	filtered := make([]ImageCatalogEntry, 0, len(images))
	deleted := false
	for _, image := range images {
		if image.Ref == ref {
			deleted = true
			continue
		}
		filtered = append(filtered, image)
	}
	if !deleted {
		return fmt.Errorf("image not found")
	}
	return s.save(filtered)
}

func (s *FileImageStore) load() ([]ImageCatalogEntry, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	var images []ImageCatalogEntry
	if err := json.Unmarshal(data, &images); err != nil {
		return nil, fmt.Errorf("decode image catalog: %w", err)
	}
	return images, nil
}

func (s *FileImageStore) save(images []ImageCatalogEntry) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(images, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := s.path + ".tmp"
	if err := os.WriteFile(tmpPath, append(data, '\n'), 0644); err != nil {
		return err
	}
	return os.Rename(tmpPath, s.path)
}
