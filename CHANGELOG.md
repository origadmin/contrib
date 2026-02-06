# Changelog

## [1.7.0](https://github.com/origadmin/contrib/compare/contrib-v1.6.0...contrib-v1.7.0) (2026-02-06)


### Features

* **ci:** simplify release-please workflow by removing redundant go work commands ([523aafa](https://github.com/origadmin/contrib/commit/523aafa067db8d30e5f9e9705de083d1ac8baa51))

## [1.6.0](https://github.com/origadmin/contrib/compare/contrib-v1.5.0...contrib-v1.6.0) (2026-02-06)


### Features

* **authz:** add ClearPolicies method and enhance authz middleware ([63354f7](https://github.com/origadmin/contrib/commit/63354f7b2d9d80dfe7bdab2d5c5af5d5d87b5af6))
* **authz:** add ClearPolicies method and enhance authz middleware ([76d4516](https://github.com/origadmin/contrib/commit/76d45167768905a85c59a489dff9155ac1aa574c))
* **authz:** add force reload capability to authz.Reloader interface ([8c37aaf](https://github.com/origadmin/contrib/commit/8c37aaf3630c5b484c5fb8153960eefd81f84aeb))
* **authz:** add PolicySpec for authorization policy storage and retrieval ([96a56f4](https://github.com/origadmin/contrib/commit/96a56f483bab40c699069b14f6e2386a2f974b94))
* **casbin:** add GetEnforcer method and refactor Reload logic ([2ac3375](https://github.com/origadmin/contrib/commit/2ac33759ec7a43bc305153039dc365c43c2aec51))


### Bug Fixes

* **security:** improve JWT authenticator and casbin authorizer logic ([717c149](https://github.com/origadmin/contrib/commit/717c149a43e643e3e841db3775d401a398adb03d))

## [1.5.0](https://github.com/origadmin/contrib/compare/contrib-v1.4.0...contrib-v1.5.0) (2026-01-28)


### Features

* **api:** add policy proto definitions and restructure security authn packages ([be88a8f](https://github.com/origadmin/contrib/commit/be88a8fd2b58f2a1ba901411105328620d23ee9a))
* **authn:** add comprehensive test suite for authentication middleware with JWT and noop providers ([6955d92](https://github.com/origadmin/contrib/commit/6955d920f1d5ad27851955439d7371fbf852b3cc))
* **authn:** add comprehensive test suite for JWT authenticator and claims implementation ([9d1d703](https://github.com/origadmin/contrib/commit/9d1d703e39fefd0c2b6fc809689b3fb35b071135))
* **authn:** add refresh credential tests and improve mock cache context handling ([5b4dcff](https://github.com/origadmin/contrib/commit/5b4dcff6a64da190fe18daa12edf09c620c4ce00))
* **authn:** add refresh token support to JWT authenticator and implement Refresher interface ([673321c](https://github.com/origadmin/contrib/commit/673321cc7468dcd1ac751523dbb04d3e8547bad1))
* **authn:** add structured logging to JWT authenticator and refactor principal creation with functional options ([f6052e7](https://github.com/origadmin/contrib/commit/f6052e7246ddcc307cbf2c74085f99b7f4cc0ac5))
* **authn:** refactor middleware factory registration and add authenticator option support ([08d586c](https://github.com/origadmin/contrib/commit/08d586ce5ab977314e5b2f78ab0036d9329b78b7))
* **authn:** refine error messages for JWT authentication test cases ([8ef71c8](https://github.com/origadmin/contrib/commit/8ef71c8dfb6334af37275b879eee06ea6aaad7b1))
* **auth:** optimize JWT and Casbin logging with context-aware logging and reduced verbosity ([c35fb5b](https://github.com/origadmin/contrib/commit/c35fb5b4372c7fdfac30a0db75a3bc2d1ae9d17a))
* **auth:** refactor casbin and jwt authentication with updated imports and package structure ([cef45bf](https://github.com/origadmin/contrib/commit/cef45bf561f468d3ee57545606bcfc791c2f1d8f))
* **auth:** refactor JWT and Casbin config handling with clear precedence rules and default behaviors ([e3f320b](https://github.com/origadmin/contrib/commit/e3f320b8b435a4f592e52b5522d026c91bb0cf31))
* **auth:** restructure JWT and Casbin authenticators with improved initialization patterns ([86ffad7](https://github.com/origadmin/contrib/commit/86ffad76ecb657fe92be352078424bf2ac2163c5))
* **authz:** add dynamic policy reload support and policy modification interface ([4d22c5b](https://github.com/origadmin/contrib/commit/4d22c5b1d708ef9a8e7b657348a62d476cee6d89))
* **authz:** add file adapter and refactor memory adapter with policy initialization ([18d950f](https://github.com/origadmin/contrib/commit/18d950f6587c5d24f2325fbda26edef636cbe476))
* **authz:** enhance Casbin authorizer with domain detection and support for domain-less models ([59eefc9](https://github.com/origadmin/contrib/commit/59eefc9f43de8a52061dd055aa63ff020edd6bb5))
* **authz:** enhance config with embedded model and wildcard support, refactor policy rules to align with Casbin format, and optimize authorizer performance ([3c0de03](https://github.com/origadmin/contrib/commit/3c0de03b95e2cdda231a8f9d007f742c286fa566))
* **authz:** implement authorization middleware with tests and factory pattern ([2e49b20](https://github.com/origadmin/contrib/commit/2e49b202f100ec156f876d9b3583724826c7fc5f))
* **authz:** refactor authorization middleware with improved rule handling and HTTP method support ([578ab32](https://github.com/origadmin/contrib/commit/578ab32a2b2c63359230434fc3697eb7bebeb576))
* **authz:** refactor casbin authorizer with improved initialization and add comprehensive tests ([512cc56](https://github.com/origadmin/contrib/commit/512cc564a79aa228d3c37b5bbdd3f5bcc0eb96ae))
* **broker:** add Watermill publisher and subscriber implementations ([8f1e3d4](https://github.com/origadmin/contrib/commit/8f1e3d4f5349b903f8f22dc6720f3dad237bd884))
* **broker:** add Watermill publisher and subscriber implementations ([42ce788](https://github.com/origadmin/contrib/commit/42ce7887580258f4cb316288174aa6e614ec63b3))
* **broker:** add Watermill publisher and subscriber implementations ([abbbd14](https://github.com/origadmin/contrib/commit/abbbd14ff435c0213eeaf7a66bb9f0f19802b57a))
* **casbin:** implement Casbin authorizer with domain support ([69b5cfb](https://github.com/origadmin/contrib/commit/69b5cfb9bce3c53953cfb1d6778a3565c5455db4))
* **ci:** replace custom release workflow with release-please for automated versioning and changelog generation ([3d54cd9](https://github.com/origadmin/contrib/commit/3d54cd9de30be2b029483afd9dee8e6750df67f6))
* **config:** add consul config source implementation with options and sync support ([8e05920](https://github.com/origadmin/contrib/commit/8e059205b73b207de8f21318f6f7dfedb38c4b9b))
* **config:** add envf source and update codec package ([a81e072](https://github.com/origadmin/contrib/commit/a81e072b482c5e2ed962911303e36ead00de5479))
* **config:** add object config source and watcher ([1508e11](https://github.com/origadmin/contrib/commit/1508e11774ae6de5bd421d9b96fb4722e303f678))
* **config:** add object config source and watcher ([154d4fa](https://github.com/origadmin/contrib/commit/154d4faf3932d97770c81260655b33fadfa4b99b))
* **config:** enhance consul config with encoder/decoder support ([2d526da](https://github.com/origadmin/contrib/commit/2d526daab8583ba6896d2ca464e98441d938ba73))
* **config:** support yaml and toml formats ([029914a](https://github.com/origadmin/contrib/commit/029914a55c8c952f3de336ab1d3079d24edc558c))
* **consul:** add config sync function and improve config handling ([069daaf](https://github.com/origadmin/contrib/commit/069daaff88fc238d52fb1a258f4b36fc178668b8))
* **context:** add span context management functions ([943ed49](https://github.com/origadmin/contrib/commit/943ed490c5ef91e3995643efdba1de67ce7813f1))
* **contrib/cache:** add go.mod and go.sum for cache contrib package ([10a1a02](https://github.com/origadmin/contrib/commit/10a1a025bac4a57897d57eddfdfb86c63efe9f16))
* **contrib/cache:** add go.mod and go.sum for cache contrib package ([a7313e1](https://github.com/origadmin/contrib/commit/a7313e19e210a1e73d6b30ca1b5ebd09c247e390))
* **contrib/config:** Update go.mod and go.sum for contrib/config ([4846d2a](https://github.com/origadmin/contrib/commit/4846d2a1bf875c0369aa6c4ff11a91781df49521))
* **contrib/config:** Update go.mod and go.sum for contrib/config ([e74f8f7](https://github.com/origadmin/contrib/commit/e74f8f7d98c26c1a1ee1205bb01c6e14a30b3a67))
* **contrib/config:** Update go.mod and go.sum for contrib/config ([9c859dc](https://github.com/origadmin/contrib/commit/9c859dcebde245bd18389e16e1f39dee492d83df))
* **contrib/consul:** Update go.mod and go.sum for contrib/consul ([8428103](https://github.com/origadmin/contrib/commit/8428103390e88f537a8206a22b364a07bfe22479))
* **contrib/consul:** Update go.mod and go.sum for contrib/consul ([3da772f](https://github.com/origadmin/contrib/commit/3da772fbe91b63825eded5478ec8d18bf43efaa0))
* **contrib/consul:** Update go.mod and go.sum for contrib/consul ([5c5f020](https://github.com/origadmin/contrib/commit/5c5f02073d455b5ba478f4e733f90e87acb5fa3b))
* **contrib/database:** Update go.mod and go.sum for contrib/database ([d71091b](https://github.com/origadmin/contrib/commit/d71091bbddbcca75d5e7969562316339b66ddade))
* **contrib/database:** Update go.mod and go.sum for contrib/database ([698ec18](https://github.com/origadmin/contrib/commit/698ec18cb0f6dc1e37f086d239713ae1e9cf7abf))
* **contrib/etcd:** Update go.mod and go.sum for contrib/etcd ([3efa785](https://github.com/origadmin/contrib/commit/3efa7856c3763257ba856f7806f97a71c019ed39))
* **contrib/framework/fiber:** Update go.mod and go.sum for contrib/framework/fiber ([3164296](https://github.com/origadmin/contrib/commit/3164296db2d7528a6f49b874c15439ecf9b94e60))
* **contrib/framework/fiber:** Update go.mod and go.sum for contrib/framework/fiber ([ab72287](https://github.com/origadmin/contrib/commit/ab72287b37b0d62349bd71f98dc3b413ef398d65))
* **contrib/framework/gins:** Update go.mod and go.sum for contrib/framework/gins ([422f42f](https://github.com/origadmin/contrib/commit/422f42ffb975d21d559b4861fedf06a4a1e17a65))
* **contrib/framework/gin:** Update go.mod and go.sum for contrib/framework/gin ([20bc9ee](https://github.com/origadmin/contrib/commit/20bc9ee9c6d3db1706cf495e65dba47e45ec20f1))
* **contrib/framework/gorilla:** Update go.mod and go.sum for contrib/framework/gorilla ([c31dc17](https://github.com/origadmin/contrib/commit/c31dc17e13056d49702d8b5031bbc96598c45f96))
* **contrib/framework/gorilla:** Update go.mod and go.sum for contrib/framework/gorilla ([7f9092c](https://github.com/origadmin/contrib/commit/7f9092cc089a3283bf56b81371e6ca1c65485fc2))
* **contrib/metrics/opentelemetry:** Update go.mod and go.sum for contrib/metrics/opentelemetry ([12fcdfc](https://github.com/origadmin/contrib/commit/12fcdfcae8ad838adc65824df0c67d34d45aada0))
* **contrib/metrics/opentelemetry:** Update go.mod and go.sum for contrib/metrics/opentelemetry ([2bd00eb](https://github.com/origadmin/contrib/commit/2bd00eb4063efc996e9e28b156952cbd15a5d4b3))
* **contrib/metrics/opentelemetry:** Update go.mod and go.sum for contrib/metrics/opentelemetry ([e56fd5e](https://github.com/origadmin/contrib/commit/e56fd5e277a391e0d6a7fd91ec62039377b4e9df))
* **contrib/metrics/prometheus:** Update go.mod and go.sum for contrib/metrics/prometheus ([4c10a68](https://github.com/origadmin/contrib/commit/4c10a682d0836ff95fc5bb28a5311ce3d42c3e79))
* **contrib/metrics/prometheus:** Update go.mod and go.sum for contrib/metrics/prometheus ([5a401a2](https://github.com/origadmin/contrib/commit/5a401a2b7bcf810f804cbf4cac75fe07c9e9c0d6))
* **contrib/middleware/gin:** Update go.mod and go.sum for contrib/middleware/gin ([54dbaf6](https://github.com/origadmin/contrib/commit/54dbaf61b2be25fee0be34615940697a39d67068))
* **contrib/middleware/gin:** Update go.mod and go.sum for contrib/middleware/gin ([244ddd6](https://github.com/origadmin/contrib/commit/244ddd68fcf8033fe06c8fe894aa2536b918531e))
* **contrib/middleware/gin:** Update go.mod and go.sum for contrib/middleware/gin ([0ca4f94](https://github.com/origadmin/contrib/commit/0ca4f94d5dd993e203db237e0b6a4b9326ef98fc))
* **contrib/middleware/gin:** Update go.mod and go.sum for contrib/middleware/gin ([af48ea6](https://github.com/origadmin/contrib/commit/af48ea6ba4dcc13a8aa13f5b118e9c18ac8f8662))
* **contrib/middleware/logger:** Update go.mod and go.sum for contrib/middleware/logger ([76d32ef](https://github.com/origadmin/contrib/commit/76d32ef2b55801649faf577fb010fff9fbb8b2cf))
* **contrib/replacer:** Update go.mod and go.sum for contrib/replacer ([ed77e93](https://github.com/origadmin/contrib/commit/ed77e9358f3aa3d08c21f2212a55709d58f7fb0c))
* **contrib/web/gorilla:** Update go.mod and go.sum for contrib/web/gorilla ([b5a5c18](https://github.com/origadmin/contrib/commit/b5a5c185a5c56e42f6d652d716665fd30f8ea5c6))
* **contrib:** add Casbin adapters for Ent and in-memory storage ([7889466](https://github.com/origadmin/contrib/commit/788946625b3225936db017af95c6fe53ec73caca))
* **contrib:** add consul config and rename discovery package ([b47aa8a](https://github.com/origadmin/contrib/commit/b47aa8a0caca1f1d62b45f738994fb1d0457a27a))
* **contrib:** add consul config and rename discovery package ([87ea9ee](https://github.com/origadmin/contrib/commit/87ea9ee1031971160affff7d90fd0e20399e15cf))
* **database:** add support for Microsoft SQL Server ([610088f](https://github.com/origadmin/contrib/commit/610088f4ef36a476f65328388329a9495dd75ee1))
* **database:** add support for multiple databases and error handling ([485ee3a](https://github.com/origadmin/contrib/commit/485ee3ac7af9c4d15589f70cf0b703e68043479c))
* **database:** create MySQL database and restructure database package ([e85fa45](https://github.com/origadmin/contrib/commit/e85fa456d55ae72d94adbc4244f36da27f620f78))
* **deps:** add Watermill broker adapter and improve registry interfaces ([28fc4e4](https://github.com/origadmin/contrib/commit/28fc4e41e6b523e9da8ca1a43f9bbf7936c12f37))
* **discovery:** add support for ETCD in kratos registry ([42d9c78](https://github.com/origadmin/contrib/commit/42d9c782ebc90bb0a07931b872b253ebd7fdf489))
* **ent:** add CRUD templates and database client ([107e4e3](https://github.com/origadmin/contrib/commit/107e4e3ae010386429d7f561390b2028ff1af7cc))
* **envf:** add NewSourceWithEnv function for custom environment ([b18b6a8](https://github.com/origadmin/contrib/commit/b18b6a883d9f1de0a493571383bf15eba5f9238b))
* **jwt:** add advanced test cases for authenticator including revocation and claims validation ([f0f733c](https://github.com/origadmin/contrib/commit/f0f733c03d36fab5bc527c93ef5e96a32ac02d6e))
* **jwt:** refactor claims into separate package with enhanced functionality and tests ([9eab48e](https://github.com/origadmin/contrib/commit/9eab48ef8f3a98d51e3597d615a66d39bd3e6312))
* **metrics:** add opentelemetry implementation for metrics ([e541b45](https://github.com/origadmin/contrib/commit/e541b45f2886b606151a3d55002e0a6c270a70b7))
* **metrics:** rename opencensus to opentelemetry ([ff09867](https://github.com/origadmin/contrib/commit/ff098676c49ecb9c344f33a89f5b7af86c08767f))
* **proto:** add authenticator configuration and update imports ([52ccbd8](https://github.com/origadmin/contrib/commit/52ccbd8a69ffac1b60b1129baa9a2596b98e2646))
* **protoc-gen-go-bridge:** add route prefix support for generated HTTP handlers ([bffcb97](https://github.com/origadmin/contrib/commit/bffcb97ba951354da09735f64b6f452f738d4d6f))
* **registry:** add consul adapter generated from consul.go ([c7b0a01](https://github.com/origadmin/contrib/commit/c7b0a01bdfa8d91f293de75e071643ec2dc1ca28))
* **runtime:** implement config-based discovery service ([f68388c](https://github.com/origadmin/contrib/commit/f68388c225e0d8c8de8cd583caab5868a23fbce5))
* **runtime:** refactoring configuration loading and registry ([f359c33](https://github.com/origadmin/contrib/commit/f359c335ee27c1e4ba77ebf49e6e5a44bc1d1001))
* **runtime:** Update go.mod and go.sum for runtime ([4ef4e93](https://github.com/origadmin/contrib/commit/4ef4e93392ebb49d2f80c98e12454c25158a17ab))
* **security-demo:** implement backend service integration with gateway ([6d26f62](https://github.com/origadmin/contrib/commit/6d26f623594e0819fc19a91148a4b4f6e3cd9d40))
* **security:** add API key and basic auth credential protobuf definitions ([f28b185](https://github.com/origadmin/contrib/commit/f28b185ab98e1159cd589e0955eb4c01a25899fa))
* **security:** add authn and authz factory implementations with provider registration ([d1c471b](https://github.com/origadmin/contrib/commit/d1c471bc1df464ebae0e8f4a95931f386ad2a961))
* **security:** add domain field to Principal for multi-tenant support ([ffa991a](https://github.com/origadmin/contrib/commit/ffa991ad11157edc97d1539f741209c224ce0bd8))
* **security:** add middleware factory for unified security handling with authn/authz/propagation support ([744d5d5](https://github.com/origadmin/contrib/commit/744d5d52d81d8d326ae57b5fdb5b79787bb6ac9a))
* **security:** add proto definitions for authentication and authorization components ([4c7fdc3](https://github.com/origadmin/contrib/commit/4c7fdc30e3205aefc4028ddce2f9f6a2b4f11af1))
* **security:** add security demo with backend, gateway and client implementations ([5d785f3](https://github.com/origadmin/contrib/commit/5d785f33e240936cb44a1d3698ab8625c4305c7d))
* **security:** deprecate SkipChecker type in favor of Skipper with clear deprecation notice ([1290922](https://github.com/origadmin/contrib/commit/1290922b5fdd6cbba77efcdc464635f5c5c89827))
* **security:** enhance authn/authz middleware tests with error cases and principal builder pattern ([1eafb42](https://github.com/origadmin/contrib/commit/1eafb42e37c1940bf0370467f5784eaeb1aeddb5))
* **security:** enhance authz flow with principal propagation and integration tests ([61b4874](https://github.com/origadmin/contrib/commit/61b4874edc10f78e467b6b59ff3f9025d6e326c9))
* **security:** enhance credential and principal propagation with gRPC support and domain context ([b589297](https://github.com/origadmin/contrib/commit/b58929778b5711581d581382ff298204c1731942))
* **security:** enhance JWT authenticator with improved revocation handling ([36c1680](https://github.com/origadmin/contrib/commit/36c16807b6b4983604cd6c89859eed11093d714f))
* **security:** enhance middleware logging with module identifiers and update example naming conventions ([de0f7dd](https://github.com/origadmin/contrib/commit/de0f7dddb4dddb3da6386b278a66bd86ca86493f))
* **security:** generate authn and authz protobuf definitions ([d5d4a83](https://github.com/origadmin/contrib/commit/d5d4a83272588fe8585bacaa61f908a3ab5c7f68))
* **security:** generate authn and authz protobuf definitions ([b206484](https://github.com/origadmin/contrib/commit/b2064846164d512b0fbad59bc8d0989227fd417b))
* **security:** implement JWT authentication with token caching and revocation support ([b8b08a6](https://github.com/origadmin/contrib/commit/b8b08a68717023e2f6da51e2e7e7922065e5b233))
* **security:** implement JWT authenticator with token generation, validation and revocation support ([6f4b82e](https://github.com/origadmin/contrib/commit/6f4b82e778ce749900ad19b07f2519e561c57dd1))
* **security:** implement JWT-based authenticator with token management ([12e2a3e](https://github.com/origadmin/contrib/commit/12e2a3e96a5b395dbc4238e8c78e5c18b8a4a481))
* **security:** implement security middleware factory and refactor principal/request packages ([adfc582](https://github.com/origadmin/contrib/commit/adfc5824040c8711a239b7ab64f75db8a6a5cf25))
* **security:** refactor authz rules and principal propagation with domain support ([d9c5570](https://github.com/origadmin/contrib/commit/d9c5570a87ee92bab9833f493a8068e1f86af991))
* **security:** refactor client middleware and principal implementation with enhanced error handling and field ordering ([7e0896b](https://github.com/origadmin/contrib/commit/7e0896bd3758a1849c6fdf051234ecc8dee439c6))
* **security:** refactor noop authenticator and add Anonymous principal helper ([115b092](https://github.com/origadmin/contrib/commit/115b0926f9d208ddc57b0a05b899f485a2488057))
* **security:** refactor principal context handling and skip logic into security package ([ab81a24](https://github.com/origadmin/contrib/commit/ab81a24ad33c7d4e3bef85fcc3fe37c2e78c0a53))
* **security:** refactor protoc-gen-go-security to use policy struct and version IDs ([2459610](https://github.com/origadmin/contrib/commit/2459610babdfb56010bd490f0f5672fee0e30492))
* **security:** restructure proto files and rename security to policy package ([925d532](https://github.com/origadmin/contrib/commit/925d5324f97e09d074f57d34579e81e7f5d3181f))
* **toolkits:** add new packages and functionalities ([81259a5](https://github.com/origadmin/contrib/commit/81259a5f965115e073308f5b459adfb91165d9db))
* **tools:** add protoc-gen-go-bridge tool with HTTP/gRPC bridge generation support ([d193132](https://github.com/origadmin/contrib/commit/d1931326fd25afd440e2f884f972d5cc0faf663e))
* **tools:** add protoc-gen-go-security plugin for policy registration with version 1.0.8 ([d806801](https://github.com/origadmin/contrib/commit/d806801b569fca654e82edbc8ea0af162f4c7c48))
* **tools:** improve protoc-gen-go-bridge template with better method handling and unimplemented method support ([dd28cea](https://github.com/origadmin/contrib/commit/dd28cea3f6674f77c133c0a2c76a6db1203f090a))
* **transport:** add Watermill transport implementation and authz enhancements ([2286e07](https://github.com/origadmin/contrib/commit/2286e07142fe2173acd8b0054c7c62bc5bccf33f))
* **v0.1:** remove unused code and simplify project structure ([139ec4c](https://github.com/origadmin/contrib/commit/139ec4c2ba60b8034aa3d9cf68d20d159e475b6c))


### Bug Fixes

* **generate:** add support for non-streaming HTTP methods in protoc-gen-go-bridge ([b5928c9](https://github.com/origadmin/contrib/commit/b5928c9ee6b838b1262c6b15a491603405db28a5))
* **generate:** conditionally generate HTTP bridge code based on bindings ([23c2a29](https://github.com/origadmin/contrib/commit/23c2a29b2f5a06c21c93a77597d6297aff2f1c4a))
* **metrics:** update data types and function signatures ([c795c28](https://github.com/origadmin/contrib/commit/c795c2848a2e63a1b1bab20e540daac9d0aa64cb))
* **security:** update error check from IsCredentialsInvalid to IsTokenInvalid in authn_authz test ([15c880a](https://github.com/origadmin/contrib/commit/15c880aa5508afe586032d74bea3efe0cdbac02b))
* **tools:** add tools.go for managing build tool dependencies ([5dad397](https://github.com/origadmin/contrib/commit/5dad397fdc185d8e45d513e9e8c4fc0d613675f4))

## [1.4.0](https://github.com/origadmin/contrib/compare/v1.3.0...v1.4.0) (2026-01-28)


### Features

* **authz:** add dynamic policy reload support and policy modification interface ([4d22c5b](https://github.com/origadmin/contrib/commit/4d22c5b1d708ef9a8e7b657348a62d476cee6d89))
* **broker:** add Watermill publisher and subscriber implementations ([abbbd14](https://github.com/origadmin/contrib/commit/abbbd14ff435c0213eeaf7a66bb9f0f19802b57a))
* **deps:** add Watermill broker adapter and improve registry interfaces ([28fc4e4](https://github.com/origadmin/contrib/commit/28fc4e41e6b523e9da8ca1a43f9bbf7936c12f37))
* **security:** deprecate SkipChecker type in favor of Skipper with clear deprecation notice ([1290922](https://github.com/origadmin/contrib/commit/1290922b5fdd6cbba77efcdc464635f5c5c89827))
* **security:** refactor principal context handling and skip logic into security package ([ab81a24](https://github.com/origadmin/contrib/commit/ab81a24ad33c7d4e3bef85fcc3fe37c2e78c0a53))
* **transport:** add Watermill transport implementation and authz enhancements ([2286e07](https://github.com/origadmin/contrib/commit/2286e07142fe2173acd8b0054c7c62bc5bccf33f))


### Bug Fixes

* **generate:** add support for non-streaming HTTP methods in protoc-gen-go-bridge ([b5928c9](https://github.com/origadmin/contrib/commit/b5928c9ee6b838b1262c6b15a491603405db28a5))
* **generate:** conditionally generate HTTP bridge code based on bindings ([23c2a29](https://github.com/origadmin/contrib/commit/23c2a29b2f5a06c21c93a77597d6297aff2f1c4a))

## [1.3.0](https://github.com/origadmin/contrib/compare/v1.2.0...v1.3.0) (2026-01-13)


### Features

* **authn:** add refresh credential tests and improve mock cache context handling ([5b4dcff](https://github.com/origadmin/contrib/commit/5b4dcff6a64da190fe18daa12edf09c620c4ce00))
* **authn:** add refresh token support to JWT authenticator and implement Refresher interface ([673321c](https://github.com/origadmin/contrib/commit/673321cc7468dcd1ac751523dbb04d3e8547bad1))
* **auth:** optimize JWT and Casbin logging with context-aware logging and reduced verbosity ([c35fb5b](https://github.com/origadmin/contrib/commit/c35fb5b4372c7fdfac30a0db75a3bc2d1ae9d17a))
* **protoc-gen-go-bridge:** add route prefix support for generated HTTP handlers ([bffcb97](https://github.com/origadmin/contrib/commit/bffcb97ba951354da09735f64b6f452f738d4d6f))
* **security:** enhance middleware logging with module identifiers and update example naming conventions ([de0f7dd](https://github.com/origadmin/contrib/commit/de0f7dddb4dddb3da6386b278a66bd86ca86493f))
* **tools:** add protoc-gen-go-bridge tool with HTTP/gRPC bridge generation support ([d193132](https://github.com/origadmin/contrib/commit/d1931326fd25afd440e2f884f972d5cc0faf663e))
* **tools:** improve protoc-gen-go-bridge template with better method handling and unimplemented method support ([dd28cea](https://github.com/origadmin/contrib/commit/dd28cea3f6674f77c133c0a2c76a6db1203f090a))

## [1.2.0](https://github.com/origadmin/contrib/compare/v1.1.0...v1.2.0) (2025-12-30)


### Features

* **auth:** restructure JWT and Casbin authenticators with improved initialization patterns ([86ffad7](https://github.com/origadmin/contrib/commit/86ffad76ecb657fe92be352078424bf2ac2163c5))

## [1.1.0](https://github.com/origadmin/contrib/compare/v1.0.0...v1.1.0) (2025-12-03)


### Features

* **config:** add consul config source implementation with options and sync support ([8e05920](https://github.com/origadmin/contrib/commit/8e059205b73b207de8f21318f6f7dfedb38c4b9b))
* **registry:** add consul adapter generated from consul.go ([c7b0a01](https://github.com/origadmin/contrib/commit/c7b0a01bdfa8d91f293de75e071643ec2dc1ca28))
* **security:** add security demo with backend, gateway and client implementations ([5d785f3](https://github.com/origadmin/contrib/commit/5d785f33e240936cb44a1d3698ab8625c4305c7d))
* **security:** implement JWT authentication with token caching and revocation support ([b8b08a6](https://github.com/origadmin/contrib/commit/b8b08a68717023e2f6da51e2e7e7922065e5b233))
* **tools:** add protoc-gen-go-security plugin for policy registration with version 1.0.8 ([d806801](https://github.com/origadmin/contrib/commit/d806801b569fca654e82edbc8ea0af162f4c7c48))


### Bug Fixes

* **tools:** add tools.go for managing build tool dependencies ([5dad397](https://github.com/origadmin/contrib/commit/5dad397fdc185d8e45d513e9e8c4fc0d613675f4))

## 1.0.0 (2025-12-02)


### Features

* **api:** add policy proto definitions and restructure security authn packages ([be88a8f](https://github.com/origadmin/contrib/commit/be88a8fd2b58f2a1ba901411105328620d23ee9a))
* **authn:** add comprehensive test suite for authentication middleware with JWT and noop providers ([6955d92](https://github.com/origadmin/contrib/commit/6955d920f1d5ad27851955439d7371fbf852b3cc))
* **authn:** add comprehensive test suite for JWT authenticator and claims implementation ([9d1d703](https://github.com/origadmin/contrib/commit/9d1d703e39fefd0c2b6fc809689b3fb35b071135))
* **authn:** add structured logging to JWT authenticator and refactor principal creation with functional options ([f6052e7](https://github.com/origadmin/contrib/commit/f6052e7246ddcc307cbf2c74085f99b7f4cc0ac5))
* **authn:** refactor middleware factory registration and add authenticator option support ([08d586c](https://github.com/origadmin/contrib/commit/08d586ce5ab977314e5b2f78ab0036d9329b78b7))
* **authn:** refine error messages for JWT authentication test cases ([8ef71c8](https://github.com/origadmin/contrib/commit/8ef71c8dfb6334af37275b879eee06ea6aaad7b1))
* **auth:** refactor casbin and jwt authentication with updated imports and package structure ([cef45bf](https://github.com/origadmin/contrib/commit/cef45bf561f468d3ee57545606bcfc791c2f1d8f))
* **auth:** refactor JWT and Casbin config handling with clear precedence rules and default behaviors ([e3f320b](https://github.com/origadmin/contrib/commit/e3f320b8b435a4f592e52b5522d026c91bb0cf31))
* **authz:** add file adapter and refactor memory adapter with policy initialization ([18d950f](https://github.com/origadmin/contrib/commit/18d950f6587c5d24f2325fbda26edef636cbe476))
* **authz:** enhance Casbin authorizer with domain detection and support for domain-less models ([59eefc9](https://github.com/origadmin/contrib/commit/59eefc9f43de8a52061dd055aa63ff020edd6bb5))
* **authz:** enhance config with embedded model and wildcard support, refactor policy rules to align with Casbin format, and optimize authorizer performance ([3c0de03](https://github.com/origadmin/contrib/commit/3c0de03b95e2cdda231a8f9d007f742c286fa566))
* **authz:** implement authorization middleware with tests and factory pattern ([2e49b20](https://github.com/origadmin/contrib/commit/2e49b202f100ec156f876d9b3583724826c7fc5f))
* **authz:** refactor authorization middleware with improved rule handling and HTTP method support ([578ab32](https://github.com/origadmin/contrib/commit/578ab32a2b2c63359230434fc3697eb7bebeb576))
* **authz:** refactor casbin authorizer with improved initialization and add comprehensive tests ([512cc56](https://github.com/origadmin/contrib/commit/512cc564a79aa228d3c37b5bbdd3f5bcc0eb96ae))
* **casbin:** implement Casbin authorizer with domain support ([69b5cfb](https://github.com/origadmin/contrib/commit/69b5cfb9bce3c53953cfb1d6778a3565c5455db4))
* **ci:** replace custom release workflow with release-please for automated versioning and changelog generation ([3d54cd9](https://github.com/origadmin/contrib/commit/3d54cd9de30be2b029483afd9dee8e6750df67f6))
* **config:** add envf source and update codec package ([a81e072](https://github.com/origadmin/contrib/commit/a81e072b482c5e2ed962911303e36ead00de5479))
* **config:** add object config source and watcher ([1508e11](https://github.com/origadmin/contrib/commit/1508e11774ae6de5bd421d9b96fb4722e303f678))
* **config:** add object config source and watcher ([154d4fa](https://github.com/origadmin/contrib/commit/154d4faf3932d97770c81260655b33fadfa4b99b))
* **config:** enhance consul config with encoder/decoder support ([2d526da](https://github.com/origadmin/contrib/commit/2d526daab8583ba6896d2ca464e98441d938ba73))
* **config:** support yaml and toml formats ([029914a](https://github.com/origadmin/contrib/commit/029914a55c8c952f3de336ab1d3079d24edc558c))
* **consul:** add config sync function and improve config handling ([069daaf](https://github.com/origadmin/contrib/commit/069daaff88fc238d52fb1a258f4b36fc178668b8))
* **context:** add span context management functions ([943ed49](https://github.com/origadmin/contrib/commit/943ed490c5ef91e3995643efdba1de67ce7813f1))
* **contrib/cache:** add go.mod and go.sum for cache contrib package ([10a1a02](https://github.com/origadmin/contrib/commit/10a1a025bac4a57897d57eddfdfb86c63efe9f16))
* **contrib/cache:** add go.mod and go.sum for cache contrib package ([a7313e1](https://github.com/origadmin/contrib/commit/a7313e19e210a1e73d6b30ca1b5ebd09c247e390))
* **contrib/config:** Update go.mod and go.sum for contrib/config ([4846d2a](https://github.com/origadmin/contrib/commit/4846d2a1bf875c0369aa6c4ff11a91781df49521))
* **contrib/config:** Update go.mod and go.sum for contrib/config ([e74f8f7](https://github.com/origadmin/contrib/commit/e74f8f7d98c26c1a1ee1205bb01c6e14a30b3a67))
* **contrib/config:** Update go.mod and go.sum for contrib/config ([9c859dc](https://github.com/origadmin/contrib/commit/9c859dcebde245bd18389e16e1f39dee492d83df))
* **contrib/consul:** Update go.mod and go.sum for contrib/consul ([8428103](https://github.com/origadmin/contrib/commit/8428103390e88f537a8206a22b364a07bfe22479))
* **contrib/consul:** Update go.mod and go.sum for contrib/consul ([3da772f](https://github.com/origadmin/contrib/commit/3da772fbe91b63825eded5478ec8d18bf43efaa0))
* **contrib/consul:** Update go.mod and go.sum for contrib/consul ([5c5f020](https://github.com/origadmin/contrib/commit/5c5f02073d455b5ba478f4e733f90e87acb5fa3b))
* **contrib/database:** Update go.mod and go.sum for contrib/database ([d71091b](https://github.com/origadmin/contrib/commit/d71091bbddbcca75d5e7969562316339b66ddade))
* **contrib/database:** Update go.mod and go.sum for contrib/database ([698ec18](https://github.com/origadmin/contrib/commit/698ec18cb0f6dc1e37f086d239713ae1e9cf7abf))
* **contrib/etcd:** Update go.mod and go.sum for contrib/etcd ([3efa785](https://github.com/origadmin/contrib/commit/3efa7856c3763257ba856f7806f97a71c019ed39))
* **contrib/framework/fiber:** Update go.mod and go.sum for contrib/framework/fiber ([3164296](https://github.com/origadmin/contrib/commit/3164296db2d7528a6f49b874c15439ecf9b94e60))
* **contrib/framework/fiber:** Update go.mod and go.sum for contrib/framework/fiber ([ab72287](https://github.com/origadmin/contrib/commit/ab72287b37b0d62349bd71f98dc3b413ef398d65))
* **contrib/framework/gins:** Update go.mod and go.sum for contrib/framework/gins ([422f42f](https://github.com/origadmin/contrib/commit/422f42ffb975d21d559b4861fedf06a4a1e17a65))
* **contrib/framework/gin:** Update go.mod and go.sum for contrib/framework/gin ([20bc9ee](https://github.com/origadmin/contrib/commit/20bc9ee9c6d3db1706cf495e65dba47e45ec20f1))
* **contrib/framework/gorilla:** Update go.mod and go.sum for contrib/framework/gorilla ([c31dc17](https://github.com/origadmin/contrib/commit/c31dc17e13056d49702d8b5031bbc96598c45f96))
* **contrib/framework/gorilla:** Update go.mod and go.sum for contrib/framework/gorilla ([7f9092c](https://github.com/origadmin/contrib/commit/7f9092cc089a3283bf56b81371e6ca1c65485fc2))
* **contrib/metrics/opentelemetry:** Update go.mod and go.sum for contrib/metrics/opentelemetry ([12fcdfc](https://github.com/origadmin/contrib/commit/12fcdfcae8ad838adc65824df0c67d34d45aada0))
* **contrib/metrics/opentelemetry:** Update go.mod and go.sum for contrib/metrics/opentelemetry ([2bd00eb](https://github.com/origadmin/contrib/commit/2bd00eb4063efc996e9e28b156952cbd15a5d4b3))
* **contrib/metrics/opentelemetry:** Update go.mod and go.sum for contrib/metrics/opentelemetry ([e56fd5e](https://github.com/origadmin/contrib/commit/e56fd5e277a391e0d6a7fd91ec62039377b4e9df))
* **contrib/metrics/prometheus:** Update go.mod and go.sum for contrib/metrics/prometheus ([4c10a68](https://github.com/origadmin/contrib/commit/4c10a682d0836ff95fc5bb28a5311ce3d42c3e79))
* **contrib/metrics/prometheus:** Update go.mod and go.sum for contrib/metrics/prometheus ([5a401a2](https://github.com/origadmin/contrib/commit/5a401a2b7bcf810f804cbf4cac75fe07c9e9c0d6))
* **contrib/middleware/gin:** Update go.mod and go.sum for contrib/middleware/gin ([54dbaf6](https://github.com/origadmin/contrib/commit/54dbaf61b2be25fee0be34615940697a39d67068))
* **contrib/middleware/gin:** Update go.mod and go.sum for contrib/middleware/gin ([244ddd6](https://github.com/origadmin/contrib/commit/244ddd68fcf8033fe06c8fe894aa2536b918531e))
* **contrib/middleware/gin:** Update go.mod and go.sum for contrib/middleware/gin ([0ca4f94](https://github.com/origadmin/contrib/commit/0ca4f94d5dd993e203db237e0b6a4b9326ef98fc))
* **contrib/middleware/gin:** Update go.mod and go.sum for contrib/middleware/gin ([af48ea6](https://github.com/origadmin/contrib/commit/af48ea6ba4dcc13a8aa13f5b118e9c18ac8f8662))
* **contrib/middleware/logger:** Update go.mod and go.sum for contrib/middleware/logger ([76d32ef](https://github.com/origadmin/contrib/commit/76d32ef2b55801649faf577fb010fff9fbb8b2cf))
* **contrib/replacer:** Update go.mod and go.sum for contrib/replacer ([ed77e93](https://github.com/origadmin/contrib/commit/ed77e9358f3aa3d08c21f2212a55709d58f7fb0c))
* **contrib/web/gorilla:** Update go.mod and go.sum for contrib/web/gorilla ([b5a5c18](https://github.com/origadmin/contrib/commit/b5a5c185a5c56e42f6d652d716665fd30f8ea5c6))
* **contrib:** add Casbin adapters for Ent and in-memory storage ([7889466](https://github.com/origadmin/contrib/commit/788946625b3225936db017af95c6fe53ec73caca))
* **contrib:** add consul config and rename discovery package ([b47aa8a](https://github.com/origadmin/contrib/commit/b47aa8a0caca1f1d62b45f738994fb1d0457a27a))
* **contrib:** add consul config and rename discovery package ([87ea9ee](https://github.com/origadmin/contrib/commit/87ea9ee1031971160affff7d90fd0e20399e15cf))
* **database:** add support for Microsoft SQL Server ([610088f](https://github.com/origadmin/contrib/commit/610088f4ef36a476f65328388329a9495dd75ee1))
* **database:** add support for multiple databases and error handling ([485ee3a](https://github.com/origadmin/contrib/commit/485ee3ac7af9c4d15589f70cf0b703e68043479c))
* **database:** create MySQL database and restructure database package ([e85fa45](https://github.com/origadmin/contrib/commit/e85fa456d55ae72d94adbc4244f36da27f620f78))
* **discovery:** add support for ETCD in kratos registry ([42d9c78](https://github.com/origadmin/contrib/commit/42d9c782ebc90bb0a07931b872b253ebd7fdf489))
* **ent:** add CRUD templates and database client ([107e4e3](https://github.com/origadmin/contrib/commit/107e4e3ae010386429d7f561390b2028ff1af7cc))
* **envf:** add NewSourceWithEnv function for custom environment ([b18b6a8](https://github.com/origadmin/contrib/commit/b18b6a883d9f1de0a493571383bf15eba5f9238b))
* **jwt:** add advanced test cases for authenticator including revocation and claims validation ([f0f733c](https://github.com/origadmin/contrib/commit/f0f733c03d36fab5bc527c93ef5e96a32ac02d6e))
* **jwt:** refactor claims into separate package with enhanced functionality and tests ([9eab48e](https://github.com/origadmin/contrib/commit/9eab48ef8f3a98d51e3597d615a66d39bd3e6312))
* **metrics:** add opentelemetry implementation for metrics ([e541b45](https://github.com/origadmin/contrib/commit/e541b45f2886b606151a3d55002e0a6c270a70b7))
* **metrics:** rename opencensus to opentelemetry ([ff09867](https://github.com/origadmin/contrib/commit/ff098676c49ecb9c344f33a89f5b7af86c08767f))
* **proto:** add authenticator configuration and update imports ([52ccbd8](https://github.com/origadmin/contrib/commit/52ccbd8a69ffac1b60b1129baa9a2596b98e2646))
* **runtime:** implement config-based discovery service ([f68388c](https://github.com/origadmin/contrib/commit/f68388c225e0d8c8de8cd583caab5868a23fbce5))
* **runtime:** refactoring configuration loading and registry ([f359c33](https://github.com/origadmin/contrib/commit/f359c335ee27c1e4ba77ebf49e6e5a44bc1d1001))
* **runtime:** Update go.mod and go.sum for runtime ([4ef4e93](https://github.com/origadmin/contrib/commit/4ef4e93392ebb49d2f80c98e12454c25158a17ab))
* **security-demo:** implement backend service integration with gateway ([6d26f62](https://github.com/origadmin/contrib/commit/6d26f623594e0819fc19a91148a4b4f6e3cd9d40))
* **security:** add API key and basic auth credential protobuf definitions ([f28b185](https://github.com/origadmin/contrib/commit/f28b185ab98e1159cd589e0955eb4c01a25899fa))
* **security:** add authn and authz factory implementations with provider registration ([d1c471b](https://github.com/origadmin/contrib/commit/d1c471bc1df464ebae0e8f4a95931f386ad2a961))
* **security:** add domain field to Principal for multi-tenant support ([ffa991a](https://github.com/origadmin/contrib/commit/ffa991ad11157edc97d1539f741209c224ce0bd8))
* **security:** add middleware factory for unified security handling with authn/authz/propagation support ([744d5d5](https://github.com/origadmin/contrib/commit/744d5d52d81d8d326ae57b5fdb5b79787bb6ac9a))
* **security:** add proto definitions for authentication and authorization components ([4c7fdc3](https://github.com/origadmin/contrib/commit/4c7fdc30e3205aefc4028ddce2f9f6a2b4f11af1))
* **security:** enhance authn/authz middleware tests with error cases and principal builder pattern ([1eafb42](https://github.com/origadmin/contrib/commit/1eafb42e37c1940bf0370467f5784eaeb1aeddb5))
* **security:** enhance authz flow with principal propagation and integration tests ([61b4874](https://github.com/origadmin/contrib/commit/61b4874edc10f78e467b6b59ff3f9025d6e326c9))
* **security:** enhance credential and principal propagation with gRPC support and domain context ([b589297](https://github.com/origadmin/contrib/commit/b58929778b5711581d581382ff298204c1731942))
* **security:** enhance JWT authenticator with improved revocation handling ([36c1680](https://github.com/origadmin/contrib/commit/36c16807b6b4983604cd6c89859eed11093d714f))
* **security:** generate authn and authz protobuf definitions ([d5d4a83](https://github.com/origadmin/contrib/commit/d5d4a83272588fe8585bacaa61f908a3ab5c7f68))
* **security:** generate authn and authz protobuf definitions ([b206484](https://github.com/origadmin/contrib/commit/b2064846164d512b0fbad59bc8d0989227fd417b))
* **security:** implement JWT authenticator with token generation, validation and revocation support ([6f4b82e](https://github.com/origadmin/contrib/commit/6f4b82e778ce749900ad19b07f2519e561c57dd1))
* **security:** implement JWT-based authenticator with token management ([12e2a3e](https://github.com/origadmin/contrib/commit/12e2a3e96a5b395dbc4238e8c78e5c18b8a4a481))
* **security:** implement security middleware factory and refactor principal/request packages ([adfc582](https://github.com/origadmin/contrib/commit/adfc5824040c8711a239b7ab64f75db8a6a5cf25))
* **security:** refactor authz rules and principal propagation with domain support ([d9c5570](https://github.com/origadmin/contrib/commit/d9c5570a87ee92bab9833f493a8068e1f86af991))
* **security:** refactor client middleware and principal implementation with enhanced error handling and field ordering ([7e0896b](https://github.com/origadmin/contrib/commit/7e0896bd3758a1849c6fdf051234ecc8dee439c6))
* **security:** refactor noop authenticator and add Anonymous principal helper ([115b092](https://github.com/origadmin/contrib/commit/115b0926f9d208ddc57b0a05b899f485a2488057))
* **security:** refactor protoc-gen-go-security to use policy struct and version IDs ([2459610](https://github.com/origadmin/contrib/commit/2459610babdfb56010bd490f0f5672fee0e30492))
* **security:** restructure proto files and rename security to policy package ([925d532](https://github.com/origadmin/contrib/commit/925d5324f97e09d074f57d34579e81e7f5d3181f))
* **toolkits:** add new packages and functionalities ([81259a5](https://github.com/origadmin/contrib/commit/81259a5f965115e073308f5b459adfb91165d9db))
* **v0.1:** remove unused code and simplify project structure ([139ec4c](https://github.com/origadmin/contrib/commit/139ec4c2ba60b8034aa3d9cf68d20d159e475b6c))


### Bug Fixes

* **metrics:** update data types and function signatures ([c795c28](https://github.com/origadmin/contrib/commit/c795c2848a2e63a1b1bab20e540daac9d0aa64cb))
* **security:** update error check from IsCredentialsInvalid to IsTokenInvalid in authn_authz test ([15c880a](https://github.com/origadmin/contrib/commit/15c880aa5508afe586032d74bea3efe0cdbac02b))
