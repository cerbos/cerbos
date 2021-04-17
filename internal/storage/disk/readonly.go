package disk

import (
	"context"
	"os"

	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/storage/common"
)

type ReadOnlyStore struct {
	*common.Notifier
	index Index
	dw    *dirWatch
}

func NewReadOnlyStore(ctx context.Context, conf *Conf) (*ReadOnlyStore, error) {
	zap.S().Named("disk.store").Infow("Creating read-only disk store", "root", conf.Directory)
	idx, err := BuildIndex(ctx, os.DirFS(conf.Directory), ".")
	if err != nil {
		return nil, err
	}

	ros := &ReadOnlyStore{index: idx, Notifier: common.NewNotifier()}

	if conf.WatchForChanges {
		dw, err := newDirWatch(ctx, conf.Directory, idx, ros.Notifier)
		if err != nil {
			return nil, err
		}

		ros.dw = dw
	}

	return ros, nil
}

func (s *ReadOnlyStore) Driver() string {
	return DriverName
}

func (s *ReadOnlyStore) GetAllPolicies(ctx context.Context) <-chan *compile.Unit {
	return s.index.GetAllPolicies(ctx)
}
