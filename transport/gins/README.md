# GINS

What is GINS?

Gin is an HTTP Web framework implemented in the Go/golang language. Simple interface, high performance.

Gin characteristic

- ** Fast ** : Routing does not use reflection, is based on Radix tree, and has low memory footprint.
- ** Middleware ** : HTTP requests can be processed by a series of middleware, such as Logger, Authorization, and GZIP. This feature is similar to the Koa framework for NodeJs. The middleware mechanism also greatly improves the extensibility of the framework.
- ** Exception Handling ** : The service is always available without downtime. Gin can capture panic and recover. And there are very convenient mechanisms for handling errors that occur during HTTP requests.
- **JSON** : Gin can parse and validate the requested JSON. This feature is especially useful for Restful API development.
- ** Routing Group ** : For example, group apis that require authorization and those that do not require authorization. Group apis of different versions. And the groups can be nested, and performance is not affected.
- ** Rendering built-in ** : Native support for JSON, XML and HTML rendering.

## Reference materials

- [GIN - Github](https://github.com/gin-gonic/gin)
- [Gin - Website](https://gin-gonic.com/)
