package confdocs

import "go.uber.org/zap"

type Engine struct {
	log           *zap.SugaredLogger
	index         Index
	getFileNameFn func(pkgPath, structName string) string
	getRootNameFn func(pkgPath string) string
}

func NewEngine(logger *zap.SugaredLogger, index Index, getFileNameFn func(pkgPath, structName string) string,
	getRootNameFn func(pkgPath string) string) *Engine {
	return &Engine{
		log:           logger,
		index:         index,
		getFileNameFn: getFileNameFn,
		getRootNameFn: getRootNameFn,
	}
}

func (e *Engine) Run() error {
	return nil
}
