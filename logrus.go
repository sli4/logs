package logs

import (
"fmt"
"github.com/lestrrat/go-file-rotatelogs"
"github.com/rifflock/lfshook"
"github.com/sirupsen/logrus"
	"strings"
	"sync"

	//"github.com/sli4/starkCICD/examples/logrus/lt"
"path"
"runtime"
"time"
)

func init()  {
	Logger = logrus.New()
	Logger.SetFormatter(&logrus.JSONFormatter{})
	lfHook := newLfsHook(100, "logs/logrus")

	Logger.AddHook(LineNoHook{})
	Logger.AddHook(lfHook)
}

var Logger *logrus.Logger
//var Loggerf *logrus.Logger



func NewLogger(logName string) {
	Logger = logrus.New()
	Logger.SetReportCaller(true)
	//Loggerf = logrus.New()

	//Logger.SetFormatter(&logrus.JSONFormatter{})
	//Loggerf.SetFormatter(&logrus.JSONFormatter{})

	//Logger.AddHook(LineNoHook{c: 8})
	//Loggerf.AddHook(LineNoHook{c: 9})

	lfHook := newLfsHook(100, logName)
	Logger.AddHook(lfHook)
	Logger.WithFields(logrus.Fields{"source": "nofile"})
	//Loggerf.WithFields(logrus.Fields{"source": "nofile"})
}

func Info(args ...interface{}) {
	Logger.Info(args...)
}
func Infof(format string, args ...interface{}) {
	Logger.Infof(format, args...)
}

func Error(args ...interface{}) {
	Logger.Error(args...)
}
func Errorf(format string, args ...interface{}) {
	Logger.Errorf(format, args...)
}

func Fatal(args ...interface{}) {
	Logger.Fatal(args...)
}

type LineNoHook struct{
	c int
}

// Levels ...
func (hook LineNoHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire ...
func (hook LineNoHook) Fire(entry *logrus.Entry) error {
	entry.Caller = getCaller()

	_, file, line, ok := runtime.Caller(hook.c );
	if ok {
		//funcName := runtime.FuncForPC(pc).Name()

		entry.Data["source"] = fmt.Sprintf("%s:%v", path.Base(file), line)
	} else {
		entry.Data["source"] = fmt.Sprintf("%s:%v", "why", line)
	}

	return nil
}


func newLfsHook(maxRemainCnt int, logName string) logrus.Hook {
	fmt.Println("logname:", logName)
	writer, err := rotatelogs.New(
		logName+".%Y%m%d",
		// WithLinkName为最新的日志建立软连接,以方便随着找到当前日志文件
		rotatelogs.WithLinkName(logName),

		// WithRotationTime设置日志分割的时间,这里设置为一小时分割一次
		rotatelogs.WithRotationTime(time.Hour),

		// WithMaxAge和WithRotationCount二者只能设置一个,
		// WithMaxAge设置文件清理前的最长保存时间,
		// WithRotationCount设置文件清理前最多保存的个数.
		//rotatelogs.WithMaxAge(time.Hour*24),
		rotatelogs.WithRotationCount(maxRemainCnt),
	)

	if err != nil {
		logrus.Errorf("config local file system for logger error: %v", err)
	}

	lfsHook := lfshook.NewHook(lfshook.WriterMap{
		logrus.DebugLevel: writer,
		logrus.InfoLevel:  writer,
		logrus.WarnLevel:  writer,
		logrus.ErrorLevel: writer,
		logrus.FatalLevel: writer,
		logrus.PanicLevel: writer,
	}, &logrus.TextFormatter{DisableColors: true})

	return lfsHook
}



var (
	bufferPool *sync.Pool

	// qualified package name, cached at first use
	logsPackage string

	// Positions in the call stack when tracing to report the calling method
	minimumCallerDepth int

	// Used for caller information initialisation
	callerInitOnce sync.Once
)

const (
	maximumCallerDepth int = 25
	knownLogsFrames  int = 10
)


func getPackageName(f string) string {
	for {
		lastPeriod := strings.LastIndex(f, ".")
		lastSlash := strings.LastIndex(f, "/")
		if lastPeriod > lastSlash {
			f = f[:lastPeriod]
		} else {
			break
		}
	}

	return f
}

func getCaller() *runtime.Frame {

	// cache this package's fully-qualified name
	callerInitOnce.Do(func() {
		pcs := make([]uintptr, 2)
		_ = runtime.Callers(0, pcs)
		logsPackage = getPackageName(runtime.FuncForPC(pcs[1]).Name())

		// now that we have the cache, we can skip a minimum count of known-logrus functions
		// XXX this is dubious, the number of frames may vary
		minimumCallerDepth = knownLogsFrames
	})

	//fmt.Printf("logrusPackage:%v\n", logsPackage)
	//fmt.Printf("minimumCallerDepth:%v\n", minimumCallerDepth)

	// Restrict the lookback frames to avoid runaway lookups
	pcs := make([]uintptr, maximumCallerDepth)
	depth := runtime.Callers(minimumCallerDepth, pcs)
	frames := runtime.CallersFrames(pcs[:depth])
	for f, again := frames.Next(); again; f, again = frames.Next() {
		pkg := getPackageName(f.Function)

		// If the caller isn't part of this package, we're done
		if pkg != logsPackage {
			return &f
		}
	}
	// if we got here, we failed to find the caller's context
	return nil
}
