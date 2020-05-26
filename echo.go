/*
Package echo implements high performance, minimalist Go web framework.

Example:

  package main

  import (
    "net/http"

    "github.com/labstack/echo/v4"
    "github.com/labstack/echo/v4/middleware"
  )

  // Handler
  func hello(c echo.Context) error {
    return c.String(http.StatusOK, "Hello, World!")
  }

  func main() {
    // Echo instance
    e := echo.New()

    // Middleware
    e.Use(middleware.Logger())
    e.Use(middleware.Recover())

    // Routes
    e.GET("/", hello)

    // Start server
    e.Logger.Fatal(e.Start(":1323"))
  }

Learn more at https://echo.labstack.com
*/
package echo

import (
	"bytes"
	stdContext "context"                   // 框架中上下文被定义为一次请求   
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	stdLog "log"                           // 框架中使用自己定义的log
	"net"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"time"

	"github.com/labstack/gommon/color"    // shell的颜色
	"github.com/labstack/gommon/log"      // 自定义实现的log
	"golang.org/x/crypto/acme"            // TLS使用
	"golang.org/x/crypto/acme/autocert"   // TLS使用
)

type (
	// Echo 结构体主要实现了服务器
	// 服务器配套的日志、调试、路由、中间件、数据绑定器 等全局资源
	// Echo is the top-level framework instance.
	Echo struct {
		common                              //
		StdLogger        *stdLog.Logger     // 类库提供的标准日志器
		colorer          *color.Color       // 颜色器
		premiddleware    []MiddlewareFunc
		middleware       []MiddlewareFunc
		maxParam         *int
		router           *Router            // 路由
		routers          map[string]*Router // 路由设置
		notFoundHandler  HandlerFunc        // 未找到Handler
		pool             sync.Pool          // 资源池    存放已经分配的但是暂时不用的对象，在需要用到的时候直接从pool中取
		Server           *http.Server       // http服务器
		TLSServer        *http.Server       // https服务器
		Listener         net.Listener       // http监听器
		TLSListener      net.Listener       // https监听器
		AutoTLSManager   autocert.Manager
		DisableHTTP2     bool               // 是否开启HTTP2协议
		Debug            bool               // 调试
		HideBanner       bool               // 服务启动是否隐藏Banner
		HidePort         bool               // 服务启动是否隐藏Port
		HTTPErrorHandler HTTPErrorHandler   // 错误句柄
		Binder           Binder             // 绑定器
		Validator        Validator          // 
		Renderer         Renderer           // 
		Logger           Logger             // 自定义实现的日志器
	}

	// Route 结构定义了一条路由的格式
	// Route contains a handler and information for matching against requests.
	Route struct {
		Method string `json:"method"`   // 路由方法
		Path   string `json:"path"`     // 路由路径
		Name   string `json:"name"`     // 路由名称
	}

	// HTTPError 结构定义了HTTP错误信息
	// HTTPError represents an error that occurred while handling a request.
	HTTPError struct {
		Code     int          // 错误码
		Message  interface{}  // 错误信息
		Internal error        // Stores the error returned by an external dependency
	}

	// 定义中间件句柄类型
	// MiddlewareFunc defines a function to process middleware.
	MiddlewareFunc func(HandlerFunc) HandlerFunc

	// HandlerFunc 函数声明  处理句柄    
	// 路由匹配的时候 调用对应的处理句柄
	// HandlerFunc defines a function to serve HTTP requests.
	HandlerFunc func(Context) error

	// HTTPErrorHandler 函数声明  HTTP错误句柄
	// HTTPErrorHandler is a centralized HTTP error handler.
	HTTPErrorHandler func(error, Context)

	// Validator  接口声明   验证器
	// Validator is the interface that wraps the Validate function.
	Validator interface {
		Validate(i interface{}) error
	}

	// Renderer  接口声明    渲染器 
	// Renderer is the interface that wraps the Render function.
	Renderer interface {
		Render(io.Writer, string, interface{}, Context) error
	}

	// Map 数据声明    字符串键映射的常规存储数据 
	// Map defines a generic map of type `map[string]interface{}`.
	Map map[string]interface{}

	// common 空结构体声明    
	// Common struct for Echo & Group.
	common struct{}
)

// HTTP methods
// NOTE: Deprecated, please use the stdlib constants directly instead.
const (
	CONNECT = http.MethodConnect   // 通过明文HTTP形式向代理服务器发送一个CONNECT请求告诉它目标站点地址及端口号；只有当浏览器配置为使用代理服务器时才会用到CONNECT方法。
	DELETE  = http.MethodDelete    // 删除
	GET     = http.MethodGet       // 获取
	HEAD    = http.MethodHead      // HEAD     方法的响应不应包含响应正文；下载一个大文件前先获取其大小再决定是否要下载, 以此可以节约带宽资源.
	OPTIONS = http.MethodOptions   // OPTIONS  方法用于描述目标资源的通信选项。
	PATCH   = http.MethodPatch     // PATCH    方法用于对资源进行部分修改。
	POST    = http.MethodPost      // POST     方法 发送数据给服务器；一般用于资源的新增
	// PROPFIND = "PROPFIND"       // 
	PUT   = http.MethodPut         // PUT      方法使用请求中的负载创建或者替换目标资源。
	TRACE = http.MethodTrace       // TRACE    方法 实现沿通向目标资源的路径的消息环回（loop-back）测试 ，提供了一种实用的 debug 机制。服务器原样返回任何客户端请求的内容。
)

// Content-Type（MediaType），即是Internet Media Type，互联网媒体类型，也叫做MIME类型。用于区分数据类型。
// 在HTTP协议消息头中，使用Content-Type来表示请求和响应中的媒体类型信息。
// MIME types
const (
	MIMEApplicationJSON                  = "application/json"                              // JSON MIME 格式
	MIMEApplicationJSONCharsetUTF8       = MIMEApplicationJSON + "; " + charsetUTF8
	MIMEApplicationJavaScript            = "application/javascript"                        // Javascript MIME 格式
	MIMEApplicationJavaScriptCharsetUTF8 = MIMEApplicationJavaScript + "; " + charsetUTF8
	MIMEApplicationXML                   = "application/xml"                               // XML MIME 格式    根据xml头指定的编码格式来编码
	MIMEApplicationXMLCharsetUTF8        = MIMEApplicationXML + "; " + charsetUTF8
	MIMETextXML                          = "text/xml"                                      // XML MIME 格式    忽略xml头所指定编码格式而默认采用us-ascii编码
	MIMETextXMLCharsetUTF8               = MIMETextXML + "; " + charsetUTF8
	MIMEApplicationForm                  = "application/x-www-form-urlencoded"             // Form表单编码方式，浏览器把form数据转换成一个字串（name1=value1&name2=value2…），然后把这个字串append到url后面
	MIMEApplicationProtobuf              = "application/protobuf"                          // Google团队开发的用于高效存储和读取结构化数据的工具。大约是json格式的1/10，xml格式的1/20
	MIMEApplicationMsgpack               = "application/msgpack"                           // 是一个高效的二进制序列化格式。比JSON更快、更小。
	MIMETextHTML                         = "text/html"                                     // text/html格式，浏览器在获取到这种文件时会自动调用html的解析器对文件进行相应的处理。
	MIMETextHTMLCharsetUTF8              = MIMETextHTML + "; " + charsetUTF8
	MIMETextPlain                        = "text/plain"                                    // text/plain格式，浏览器在获取到这种文件时并不会对其进行处理。
	MIMETextPlainCharsetUTF8             = MIMETextPlain + "; " + charsetUTF8
	MIMEMultipartForm                    = "multipart/form-data"                           // Form表单编码方式，浏览器把form数据封装到http body中，然后发送到server。如果有type=file的话，就要用到multipart/form-data。
	                                                                                       // 浏览器会把整个表单以控件为单位分割，并为每个部分加上Content-Disposition(form-data或者file),Content-Type(默认为text/plain),name(控件name)等信息，并加上分割符(boundary)。
	MIMEOctetStream                      = "application/octet-stream"                      // 二进制（八位字节流）格式
)

const (
	charsetUTF8 = "charset=UTF-8"                                                          // UTF-8 编码
	// PROPFIND Method can be used on collection and property resources.
	PROPFIND = "PROPFIND"                                                                  // PROPFIND 方法可用于集合和属性资源    查看属性(wedav)
	// REPORT Method can be used to get information about a resource, see rfc 3253
	REPORT = "REPORT"                                                                      // REPORT 方法用于获取一个资源的信息
)

// Headers
const (
	HeaderAccept              = "Accept"                    // 请求 - 可接受的响应内容类型（Content-Types）
	HeaderAcceptEncoding      = "Accept-Encoding"           // 请求 - 可接受的响应内容的编码方式。  gzip, deflate
	HeaderAllow               = "Allow"                     // 响应 - 对于特定资源的有效动作
	HeaderAuthorization       = "Authorization"             // 请求 - 用于表示HTTP协议中需要认证资源的认证信息
	HeaderContentDisposition  = "Content-Disposition"       // 响应 - 对已知MIME类型资源的描述，浏览器可以根据这个响应头决定是对返回资源的动作，如：将其下载或是打开。
	HeaderContentEncoding     = "Content-Encoding"          // 响应 - 响应资源所使用的编码类型。
	HeaderContentLength       = "Content-Length"            // 响应 - 响应消息体的长度，用8进制字节表示
	HeaderContentType         = "Content-Type"              // 响应 - 当前内容的MIME类型
	HeaderCookie              = "Cookie"                    // 请求 - 由之前服务器通过Set-Cookie（见下文）设置的一个HTTP协议Cookie
	HeaderSetCookie           = "Set-Cookie"                // 响应 - 设置HTTP cookie
	HeaderIfModifiedSince     = "If-Modified-Since"         // 请求 - 允许在对应的资源未被修改的情况下返回304未修改
	HeaderLastModified        = "Last-Modified"             // 响应 - 所请求的对象的最后修改日期(按照 RFC 7231 中定义的“超文本传输协议日期”格式来表示)
	HeaderLocation            = "Location"                  // 响应 - 用于在进行重定向，或在创建了某个新资源时使用。
	HeaderUpgrade             = "Upgrade"                   // 响应 - 要求客户端升级到另一个高版本协议。
	HeaderVary                = "Vary"                      // 响应 - 告知下游的代理服务器，应当如何对以后的请求协议头进行匹配，以决定是否可使用已缓存的响应内容而不是重新从原服务器请求新的内容。
	HeaderWWWAuthenticate     = "WWW-Authenticate"          // 响应 - 表示在请求获取这个实体时应当使用的认证模式。
	HeaderXForwardedFor       = "X-Forwarded-For"           // 请求 - 识别通过HTTP代理或负载均衡方式连接到Web服务器的客户端最原始的IP地址的HTTP请求头字段。 
	                                                        //       每经过一级代理(匿名代理除外)，代理服务器都会把这次请求的来源IP追加在X-Forwarded-For中
	HeaderXForwardedProto     = "X-Forwarded-Proto"         // 请求 - 用于识别协议（HTTP 或 HTTPS），其中使用的客户端连接到代理或负载平衡器一个事实上的标准报头。
	HeaderXForwardedProtocol  = "X-Forwarded-Protocol"
	HeaderXForwardedSsl       = "X-Forwarded-Ssl"
	HeaderXUrlScheme          = "X-Url-Scheme"
	HeaderXHTTPMethodOverride = "X-HTTP-Method-Override"    // 请求 - 客户端发出 HTTP POST 请求并设置 X-HTTP-Method-Override 标头的值为想要的 HTTP 方法（比如 PATCH ）
	HeaderXRealIP             = "X-Real-IP"                 // 请求 - 只记录真实发出请求的客户端IP
	HeaderXRequestID          = "X-Request-ID"              // 响应 - 标识客户端和服务端的HTTP请求
	HeaderXRequestedWith      = "X-Requested-With"          // 请求 - AJax异步（判断同步还是异步）
	HeaderServer              = "Server"                    // 响应 - 用作原始服务器处理请求的软件信息
	HeaderOrigin              = "Origin"                    // 请求 - 指示其中从取起源。它与Referer标题相似，但与此标题不同，它没有公开整个路径。

	// Access control
	HeaderAccessControlRequestMethod    = "Access-Control-Request-Method"       // 请求 - 用于预检请求让服务器知道哪些 HTTP 方法的实际请求时将被使用。
	HeaderAccessControlRequestHeaders   = "Access-Control-Request-Headers"      // 请求 - 用于预检请求让服务器知道哪些 HTTP 头的实际请求时将被使用。
	HeaderAccessControlAllowOrigin      = "Access-Control-Allow-Origin"         // 响应 - 指示是否该响应可以与具有给定资源共享原点
	HeaderAccessControlAllowMethods     = "Access-Control-Allow-Methods"        // 响应 - 指定响应访问所述资源到时允许的一种或多种方法预检请求
	HeaderAccessControlAllowHeaders     = "Access-Control-Allow-Headers"        // 响应 - 用于一个预检请求指示哪个HTTP标头将通过提供Access-Control-Expose-Headers使实际的请求时。
	HeaderAccessControlAllowCredentials = "Access-Control-Allow-Credentials"    // 响应 - 请求的响应是否可以暴露于该页面。当true值返回时它可以被暴露。
	HeaderAccessControlExposeHeaders    = "Access-Control-Expose-Headers"       // 响应 - 指示哪些报头可以公开为通过列出他们的名字的响应的一部分
	HeaderAccessControlMaxAge           = "Access-Control-Max-Age"              // 响应 - 指示多长时间的结果预检请求（即包含在所述信息Access-Control-Allow-Methods和Access-Control-Allow-Headers的 headers ）可以被缓存。

	// Security
	HeaderStrictTransportSecurity         = "Strict-Transport-Security"            // 响应 - 是一种安全功能（通常缩写为 HSTS），可以让一个网站告诉大家，它应该只使用 HTTPS，而不是使用 HTTP 进行通信的浏览器。
	HeaderXContentTypeOptions             = "X-Content-Type-Options"               // 响应 - 是由服务器使用以指示在通告的 MIME 类型的标记Content-Type标头不应该被改变，并且被遵循。
	HeaderXXSSProtection                  = "X-XSS-Protection"                     // 响应 - 可在检测到反射的跨站点脚本（XSS）攻击时阻止页面加载。
	HeaderXFrameOptions                   = "X-Frame-Options"                      // 响应 - 可以被用来指示一个浏览器是否应该被允许在一个以呈现页面<frame>，<iframe>或<object>
	HeaderContentSecurityPolicy           = "Content-Security-Policy"              // 响应 - 内容安全政策,简称为CSP。指示浏览器你只能加载那些规则下的js代码，其他的都一律拒绝。
	HeaderContentSecurityPolicyReportOnly = "Content-Security-Policy-Report-Only"  // 响应 - 允许Web开发人员通过监视（但不强制执行）其效果来实验策略。
	HeaderXCSRFToken                      = "X-CSRF-Token"                         // 响应 - 防御CSRF攻击
)

const (
	// Version of Echo
	Version = "4.1.6"
	website = "https://echo.labstack.com"
	// http://patorjk.com/software/taag/#p=display&f=Small%20Slant&t=Echo
	banner = `
   ____    __
  / __/___/ /  ___
 / _// __/ _ \/ _ \
/___/\__/_//_/\___/ %s
High performance, minimalist Go web framework
%s
____________________________________O/_______
                                    O\
`
)

var (
	methods = [...]string{          // 定义HTTP方法
		http.MethodConnect,
		http.MethodDelete,
		http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		PROPFIND,
		http.MethodPut,
		http.MethodTrace,
		REPORT,
	}
)

// Errors
var (
	ErrUnsupportedMediaType        = NewHTTPError(http.StatusUnsupportedMediaType)      // 415 媒体类型不支持
	ErrNotFound                    = NewHTTPError(http.StatusNotFound)                  // 404 未找到
	ErrUnauthorized                = NewHTTPError(http.StatusUnauthorized)              // 401 未认证
	ErrForbidden                   = NewHTTPError(http.StatusForbidden)                 // 403 资源已关闭
	ErrMethodNotAllowed            = NewHTTPError(http.StatusMethodNotAllowed)          // 405 方法不允许
	ErrStatusRequestEntityTooLarge = NewHTTPError(http.StatusRequestEntityTooLarge)     // 413 服务器拒绝处理当前请求，因为该请求提交的实体数据大小超过了服务器愿意或者能够处理的范围。
	ErrTooManyRequests             = NewHTTPError(http.StatusTooManyRequests)           // 429 太多请求
	ErrBadRequest                  = NewHTTPError(http.StatusBadRequest)                // 400 语义有误，当前请求无法被服务器理解
	ErrBadGateway                  = NewHTTPError(http.StatusBadGateway)                // 502 作为网关或者代理工作的服务器尝试执行请求时，从上游服务器接收到无效的响应。
	ErrInternalServerError         = NewHTTPError(http.StatusInternalServerError)       // 500 服务器遇到了一个未曾预料的状况，导致了它无法完成对请求的处理。
	ErrRequestTimeout              = NewHTTPError(http.StatusRequestTimeout)            // 408 请求超时
	ErrServiceUnavailable          = NewHTTPError(http.StatusServiceUnavailable)        // 503 由于临时的服务器维护或者过载，服务器当前无法处理请求。
	ErrValidatorNotRegistered      = errors.New("validator not registered")                           // 验证程序未注册
	ErrRendererNotRegistered       = errors.New("renderer not registered")                            // 渲染器未注册
	ErrInvalidRedirectCode         = errors.New("invalid redirect status code")                       // 无效的重定向状态代码
	ErrCookieNotFound              = errors.New("cookie not found")                                   // cookie 未找到
	ErrInvalidCertOrKeyType        = errors.New("invalid cert or key type, must be string or []byte") // 无效的证书或密钥类型，必须是字符串或[]字节
)

// Error handlers
var (
	//未找到错误处理句柄
	NotFoundHandler = func(c Context) error {
		return ErrNotFound
	}

	// 方法不允许错误处理句柄
	MethodNotAllowedHandler = func(c Context) error {
		return ErrMethodNotAllowed
	}
)

// 创建一个新的Echo对象
// New creates an instance of Echo.
func New() (e *Echo) {
	e = &Echo{
		Server:    new(http.Server),
		TLSServer: new(http.Server),
		AutoTLSManager: autocert.Manager{
			Prompt: autocert.AcceptTOS,
		},
		Logger:   log.New("echo"),
		colorer:  color.New(),
		maxParam: new(int),
	}
	e.Server.Handler = e                 // HTTP 服务器 Handler          
	e.TLSServer.Handler = e              // HTTPS服务器 Handler
	e.HTTPErrorHandler = e.DefaultHTTPErrorHandler     // 错误处理 Handler （默认的错误处理Handler）
	e.Binder = &DefaultBinder{}                        // 绑定器  （默认绑定器）
	e.Logger.SetLevel(log.ERROR)                       // 设置日志器的记录级别
	e.StdLogger = stdLog.New(e.Logger.Output(), e.Logger.Prefix()+": ", 0)  // 设置标准日志记录器
	e.pool.New = func() interface{} {                  // 资源池创建一个New方法
		return e.NewContext(nil, nil)                  // 资源池返回一个新的请求上下文对象
	}                                                  // 通过对上下文资源的重用，提高系统性能（不用重复初始化请求的上下文）
	e.router = NewRouter(e)                            // 路由器 （新建立一个路由器）
	e.routers = map[string]*Router{}                   // 路由规则
	return
}

// 初始化一个请求上下文对象
// NewContext returns a Context instance.
func (e *Echo) NewContext(r *http.Request, w http.ResponseWriter) Context {
	return &context{
		request:  r,                            // http 请求对象
		response: NewResponse(w, e),            // 创建一个新的响应对象
		store:    make(Map),                    // 上下文中存储的数据是一个 map[string]inerface{} 映射类型数据
		echo:     e,                            // 服务器对象
		pvalues:  make([]string, *e.maxParam),  // 
		handler:  NotFoundHandler,              // 处理句柄（默认为未找到处理句柄）
	}
}

// 返回默认的路由器
// Router returns the default router.
func (e *Echo) Router() *Router {
	return e.router
}

// 返回路由表
// Routers returns the map of host => router.
func (e *Echo) Routers() map[string]*Router {
	return e.routers
}

// HTTP默认的错误处理程序
// DefaultHTTPErrorHandler is the default HTTP error handler. It sends a JSON response
// with status code.
func (e *Echo) DefaultHTTPErrorHandler(err error, c Context) {
	//初始响应码和响应内容
	var (
		code = http.StatusInternalServerError
		msg  interface{}
	)

	//从 HTTPError 类型数据中提取 响应码和响应内容
	if he, ok := err.(*HTTPError); ok {
		code = he.Code
		msg = he.Message
		if he.Internal != nil {
			err = fmt.Errorf("%v, %v", err, he.Internal)
		}
	} else if e.Debug {
		//如果是调试的话，响应内容为自定义的错误信息
		msg = err.Error()
	} else {
		// 默认响应内容是响应码对应的描述文字
		msg = http.StatusText(code)
	}
	
	//如果响应内容是字符串，则转化为Map映射类型。方便转化为JSON
	if _, ok := msg.(string); ok {
		msg = Map{"message": msg}
	}

	// 没有发送响应头则，发送响应头信息
	// Send response
	if !c.Response().Committed {
		if c.Request().Method == http.MethodHead { // Issue #608
			// HEAD 方式请求只发送响应头（只写状态码）
			err = c.NoContent(code)
		} else {
			// 其他请求方式发送JSON格式的响应信息
			err = c.JSON(code, msg)
		}
		// 记录错误日志信息
		if err != nil {
			e.Logger.Error(err)
		}
	}
}

// Pre adds middleware to the chain which is run before router.
func (e *Echo) Pre(middleware ...MiddlewareFunc) {
	e.premiddleware = append(e.premiddleware, middleware...)
}

// Use adds middleware to the chain which is run after router.
func (e *Echo) Use(middleware ...MiddlewareFunc) {
	e.middleware = append(e.middleware, middleware...)
}

// 注册一个 CONNECT 路由
// CONNECT registers a new CONNECT route for a path with matching handler in the
// router with optional route-level middleware.
func (e *Echo) CONNECT(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodConnect, path, h, m...)
}

// 注册一个 DELETE 路由
// DELETE registers a new DELETE route for a path with matching handler in the router
// with optional route-level middleware.
func (e *Echo) DELETE(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodDelete, path, h, m...)
}

// 注册一个 GET 路由
// GET registers a new GET route for a path with matching handler in the router
// with optional route-level middleware.
func (e *Echo) GET(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodGet, path, h, m...)
}

// 注册一个 HEAD 路由
// HEAD registers a new HEAD route for a path with matching handler in the
// router with optional route-level middleware.
func (e *Echo) HEAD(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodHead, path, h, m...)
}

// 注册一个 OPTIONS 路由
// OPTIONS registers a new OPTIONS route for a path with matching handler in the
// router with optional route-level middleware.
func (e *Echo) OPTIONS(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodOptions, path, h, m...)
}

// 注册一个 PATCH 路由
// PATCH registers a new PATCH route for a path with matching handler in the
// router with optional route-level middleware.
func (e *Echo) PATCH(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodPatch, path, h, m...)
}

// 注册一个 POST 路由
// POST registers a new POST route for a path with matching handler in the
// router with optional route-level middleware.
func (e *Echo) POST(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodPost, path, h, m...)
}

// 注册一个 PUT 路由
// PUT registers a new PUT route for a path with matching handler in the
// router with optional route-level middleware.
func (e *Echo) PUT(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodPut, path, h, m...)
}

// 注册一个 TRACE 路由
// TRACE registers a new TRACE route for a path with matching handler in the
// router with optional route-level middleware.
func (e *Echo) TRACE(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodTrace, path, h, m...)
}

// 注册一个包含所有请求方法的路由
// Any registers a new route for all HTTP methods and path with matching handler
// in the router with optional route-level middleware.
func (e *Echo) Any(path string, handler HandlerFunc, middleware ...MiddlewareFunc) []*Route {
	routes := make([]*Route, len(methods))
	for i, m := range methods {
		routes[i] = e.Add(m, path, handler, middleware...)
	}
	return routes
}

// 注册一个多请求方法的路由
// Match registers a new route for multiple HTTP methods and path with matching
// handler in the router with optional route-level middleware.
func (e *Echo) Match(methods []string, path string, handler HandlerFunc, middleware ...MiddlewareFunc) []*Route {
	routes := make([]*Route, len(methods))
	for i, m := range methods {
		routes[i] = e.Add(m, path, handler, middleware...)
	}
	return routes
}

// 注册一个静态路由
// Static registers a new route with path prefix to serve static files from the
// provided root directory.
func (e *Echo) Static(prefix, root string) *Route {
	if root == "" {
		root = "." // For security we want to restrict to CWD.
	}
	return e.static(prefix, root, e.GET)
}

// 静态路由注册（公共共有）
func (common) static(prefix, root string, get func(string, HandlerFunc, ...MiddlewareFunc) *Route) *Route {
	h := func(c Context) error {
		p, err := url.PathUnescape(c.Param("*"))
		if err != nil {
			return err
		}
		name := filepath.Join(root, path.Clean("/"+p)) // "/"+ for security
		return c.File(name)
	}
	if prefix == "/" {
		return get(prefix+"*", h)
	}
	return get(prefix+"/*", h)
}

func (common) file(path, file string, get func(string, HandlerFunc, ...MiddlewareFunc) *Route,
	m ...MiddlewareFunc) *Route {
	return get(path, func(c Context) error {
		return c.File(file)
	}, m...)
}

// 注册一个静态文件路由
// File registers a new route with path to serve a static file with optional route-level middleware.
func (e *Echo) File(path, file string, m ...MiddlewareFunc) *Route {
	return e.file(path, file, e.GET, m...)
}

func (e *Echo) add(host, method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Route {
	name := handlerName(handler)
	router := e.findRouter(host)
	router.Add(method, path, func(c Context) error {
		h := handler
		// Chain middleware
		for i := len(middleware) - 1; i >= 0; i-- {
			h = middleware[i](h)
		}
		return h(c)
	})
	r := &Route{
		Method: method,
		Path:   path,
		Name:   name,
	}
	e.router.routes[method+path] = r
	return r
}

//注册一个指定请求方法的路由
// Add registers a new route for an HTTP method and path with matching handler
// in the router with optional route-level middleware.
func (e *Echo) Add(method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Route {
	return e.add("", method, path, handler, middleware...)
}

// 使用Host（站点） 创建一个路由分组
// Host creates a new router group for the provided host and optional host-level middleware.
func (e *Echo) Host(name string, m ...MiddlewareFunc) (g *Group) {
	e.routers[name] = NewRouter(e)
	g = &Group{host: name, echo: e}
	g.Use(m...)
	return
}

// 使用Prefix（前缀） 创建一个路由分组
// Group creates a new router group with prefix and optional group-level middleware.
func (e *Echo) Group(prefix string, m ...MiddlewareFunc) (g *Group) {
	g = &Group{prefix: prefix, echo: e}
	g.Use(m...)
	return
}

// 获取Handler 的URI
// URI generates a URI from handler.
func (e *Echo) URI(handler HandlerFunc, params ...interface{}) string {
	name := handlerName(handler)
	return e.Reverse(name, params...)
}

// 获取Handler 的URL
// URL is an alias for `URI` function.
func (e *Echo) URL(h HandlerFunc, params ...interface{}) string {
	return e.URI(h, params...)
}

// 通过路由名称（Handler 名称）获取路由的URI
// Reverse generates an URL from route name and provided parameters.
func (e *Echo) Reverse(name string, params ...interface{}) string {
	uri := new(bytes.Buffer)
	ln := len(params)
	n := 0
	for _, r := range e.router.routes {
		if r.Name == name {
			for i, l := 0, len(r.Path); i < l; i++ {
				if r.Path[i] == ':' && n < ln {
					for ; i < l && r.Path[i] != '/'; i++ {
					}
					uri.WriteString(fmt.Sprintf("%v", params[n]))
					n++
				}
				if i < l {
					uri.WriteByte(r.Path[i])
				}
			}
			break
		}
	}
	return uri.String()
}

// 返回路由表的一个副本集
// Routes returns the registered routes.
func (e *Echo) Routes() []*Route {
	routes := make([]*Route, 0, len(e.router.routes))
	for _, v := range e.router.routes {
		routes = append(routes, v)
	}
	return routes
}

// 从上下文池中获取一个空的上下文实例
// AcquireContext returns an empty `Context` instance from the pool.
// You must return the context by calling `ReleaseContext()`.
func (e *Echo) AcquireContext() Context {
	return e.pool.Get().(Context)
}

// 把一个上下文实例放回到上下文池
// ReleaseContext returns the `Context` instance back to the pool.
// You must call it after `AcquireContext()`.
func (e *Echo) ReleaseContext(c Context) {
	e.pool.Put(c)
}

// http.Handler 接口的实现
// ServeHTTP implements `http.Handler` interface, which serves HTTP requests.
func (e *Echo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Acquire context
	c := e.pool.Get().(*context)
	c.Reset(r, w)

	h := NotFoundHandler

	if e.premiddleware == nil {
		e.findRouter(r.Host).Find(r.Method, getPath(r), c)
		h = c.Handler()
		h = applyMiddleware(h, e.middleware...)
	} else {
		h = func(c Context) error {
			e.findRouter(r.Host).Find(r.Method, getPath(r), c)
			h := c.Handler()
			h = applyMiddleware(h, e.middleware...)
			return h(c)
		}
		h = applyMiddleware(h, e.premiddleware...)
	}

	// Execute chain
	if err := h(c); err != nil {
		e.HTTPErrorHandler(err, c)
	}

	// Release context
	e.pool.Put(c)
}

// 启动一个HTTP服务器
// Start starts an HTTP server.
func (e *Echo) Start(address string) error {
	e.Server.Addr = address
	return e.StartServer(e.Server)
}

// 启动一个HTTPS服务器
// StartTLS starts an HTTPS server.
// If `certFile` or `keyFile` is `string` the values are treated as file paths.
// If `certFile` or `keyFile` is `[]byte` the values are treated as the certificate or key as-is.
func (e *Echo) StartTLS(address string, certFile, keyFile interface{}) (err error) {
	// 证书
	var cert []byte
	if cert, err = filepathOrContent(certFile); err != nil {
		return
	}

	// 秘钥
	var key []byte
	if key, err = filepathOrContent(keyFile); err != nil {
		return
	}

	//创建并配置HTTPS服务器
	s := e.TLSServer
	s.TLSConfig = new(tls.Config)
	s.TLSConfig.Certificates = make([]tls.Certificate, 1)
	if s.TLSConfig.Certificates[0], err = tls.X509KeyPair(cert, key); err != nil {
		return
	}

	return e.startTLS(address)
}

// 文件路径或者文件内容 获取文件内容
func filepathOrContent(fileOrContent interface{}) (content []byte, err error) {
	switch v := fileOrContent.(type) {
	case string:
		// 字符串 则代表文件路径，读取文件内容
		return ioutil.ReadFile(v)
	case []byte:
		// 字节切片则代表文件内容， 返回文件内容
		return v, nil
	default:
		// 返回无效的证书或者秘钥
		return nil, ErrInvalidCertOrKeyType
	}
}

// 
// StartAutoTLS starts an HTTPS server using certificates automatically installed from https://letsencrypt.org.
func (e *Echo) StartAutoTLS(address string) error {
	s := e.TLSServer
	s.TLSConfig = new(tls.Config)
	s.TLSConfig.GetCertificate = e.AutoTLSManager.GetCertificate
	s.TLSConfig.NextProtos = append(s.TLSConfig.NextProtos, acme.ALPNProto)
	return e.startTLS(address)
}

// HTTPS服务器启动
func (e *Echo) startTLS(address string) error {
	s := e.TLSServer
	s.Addr = address
	if !e.DisableHTTP2 {
		s.TLSConfig.NextProtos = append(s.TLSConfig.NextProtos, "h2")
	}
	return e.StartServer(e.TLSServer)
}

// 启动服务器
// StartServer starts a custom http server.
func (e *Echo) StartServer(s *http.Server) (err error) {
	// Setup
	e.colorer.SetOutput(e.Logger.Output())
	s.ErrorLog = e.StdLogger
	s.Handler = e
	if e.Debug {
		e.Logger.SetLevel(log.DEBUG)
	}

	if !e.HideBanner {
		e.colorer.Printf(banner, e.colorer.Red("v"+Version), e.colorer.Blue(website))
	}

	if s.TLSConfig == nil {
		if e.Listener == nil {
			e.Listener, err = newListener(s.Addr)
			if err != nil {
				return err
			}
		}
		if !e.HidePort {
			e.colorer.Printf("⇨ http server started on %s\n", e.colorer.Green(e.Listener.Addr()))
		}
		return s.Serve(e.Listener)
	}
	if e.TLSListener == nil {
		l, err := newListener(s.Addr)
		if err != nil {
			return err
		}
		e.TLSListener = tls.NewListener(l, s.TLSConfig)
	}
	if !e.HidePort {
		e.colorer.Printf("⇨ https server started on %s\n", e.colorer.Green(e.TLSListener.Addr()))
	}
	return s.Serve(e.TLSListener)
}

// 服务器关闭
// Close immediately stops the server.
// It internally calls `http.Server#Close()`.
func (e *Echo) Close() error {
	if err := e.TLSServer.Close(); err != nil {
		return err
	}
	return e.Server.Close()
}

// 服务器优雅关闭
// Shutdown stops the server gracefully.
// It internally calls `http.Server#Shutdown()`.
func (e *Echo) Shutdown(ctx stdContext.Context) error {
	if err := e.TLSServer.Shutdown(ctx); err != nil {
		return err
	}
	return e.Server.Shutdown(ctx)
}

// 一个新的HTTP错误
// NewHTTPError creates a new HTTPError instance.
func NewHTTPError(code int, message ...interface{}) *HTTPError {
	he := &HTTPError{Code: code, Message: http.StatusText(code)}
	if len(message) > 0 {
		he.Message = message[0]
	}
	return he
}

// 返回HTTPError的错误信息
// Error makes it compatible with `error` interface.
func (he *HTTPError) Error() string {
	return fmt.Sprintf("code=%d, message=%v", he.Code, he.Message)
}

// 在HTTPError中设置内部错误
// SetInternal sets error to HTTPError.Internal
func (he *HTTPError) SetInternal(err error) *HTTPError {
	he.Internal = err
	return he
}

// 将http.Handler的实现 包装成  echo.HandlerFunc
// WrapHandler wraps `http.Handler` into `echo.HandlerFunc`.
func WrapHandler(h http.Handler) HandlerFunc {
	return func(c Context) error {
		h.ServeHTTP(c.Response(), c.Request())
		return nil
	}
}

// 将func(http.Handler) http.Handler 包装成  echo.MiddlewareFunc
// WrapMiddleware wraps `func(http.Handler) http.Handler` into `echo.MiddlewareFunc`
func WrapMiddleware(m func(http.Handler) http.Handler) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(c Context) (err error) {
			m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c.SetRequest(r)
				err = next(c)
			})).ServeHTTP(c.Response(), c.Request())
			return
		}
	}
}

// 获取请求的Path
func getPath(r *http.Request) string {
	path := r.URL.RawPath
	if path == "" {
		path = r.URL.Path
	}
	return path
}

// 根据host查找路由
func (e *Echo) findRouter(host string) *Router {
	if len(e.routers) > 0 {
		if r, ok := e.routers[host]; ok {
			return r
		}
	}
	return e.router
}

// 返回Handler的名称（函数名）
func handlerName(h HandlerFunc) string {
	t := reflect.ValueOf(h).Type()
	if t.Kind() == reflect.Func {
		return runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
	}
	return t.String()
}

// // PathUnescape is wraps `url.PathUnescape`
// func PathUnescape(s string) (string, error) {
// 	return url.PathUnescape(s)
// }

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	if c, err = ln.AcceptTCP(); err != nil {
		return
	} else if err = c.(*net.TCPConn).SetKeepAlive(true); err != nil {
		return
	} else if err = c.(*net.TCPConn).SetKeepAlivePeriod(3 * time.Minute); err != nil {
		return
	}
	return
}

// 创建新的TCP监听器
func newListener(address string) (*tcpKeepAliveListener, error) {
	l, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	return &tcpKeepAliveListener{l.(*net.TCPListener)}, nil
}

func applyMiddleware(h HandlerFunc, middleware ...MiddlewareFunc) HandlerFunc {
	for i := len(middleware) - 1; i >= 0; i-- {
		h = middleware[i](h)
	}
	return h
}
