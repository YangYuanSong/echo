package echo

import (
	"io"

	"github.com/labstack/gommon/log"
)

type (
	// Logger defines the logging interface.
	Logger interface {
		Output() io.Writer              // 输出IO
		SetOutput(w io.Writer)          // 设置输出io
		Prefix() string                 // 前缀
		SetPrefix(p string)             // 设置前缀
		Level() log.Lvl                 // 日志等级
		SetLevel(v log.Lvl)             // 设置日志等级（DEBUG、INFO、WARN、ERROR、PANIC、FATAL）
		SetHeader(h string)             // 设置头信息
		Print(i ...interface{})         // 打印日志
		Printf(format string, args ...interface{}) // 格式化打印日志
		Printj(j log.JSON)                         // JSON格式打印日志
		Debug(i ...interface{})
		Debugf(format string, args ...interface{})
		Debugj(j log.JSON)
		Info(i ...interface{})
		Infof(format string, args ...interface{})
		Infoj(j log.JSON)
		Warn(i ...interface{})
		Warnf(format string, args ...interface{})
		Warnj(j log.JSON)
		Error(i ...interface{})
		Errorf(format string, args ...interface{})
		Errorj(j log.JSON)
		Fatal(i ...interface{})
		Fatalj(j log.JSON)
		Fatalf(format string, args ...interface{})
		Panic(i ...interface{})
		Panicj(j log.JSON)
		Panicf(format string, args ...interface{})
	}
)
