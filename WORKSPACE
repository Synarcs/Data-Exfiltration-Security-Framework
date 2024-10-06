load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "io_bazel_rules_go",
    integrity = "sha256-M6zErg9wUC20uJPJ/B3Xqb+ZjCPn/yxFF3QdQEmpdvg=",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.48.0/rules_go-v0.48.0.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.48.0/rules_go-v0.48.0.zip",
    ],
)

http_archive(
    name = "bazel_gazelle",
    integrity = "sha256-12v3pg/YsFBEQJDfooN6Tq+YKeEWVhjuNdzspcvfWNU=",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.37.0/bazel-gazelle-v0.37.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.37.0/bazel-gazelle-v0.37.0.tar.gz",
    ],
)

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")
load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

# load("//:deps.bzl", "go_dependencies")

load("//:deps.bzl", "go_dependencies")

go_repository(
    name = "com_github_google_gopacket",
    importpath = "github.com/google/gopacket",
    sum = "h1:ves8RnFZPGiFnTS0uPQStjwru6uO6h+nlr9j6fL7kF8=",
    version = "v1.1.19",
)

go_repository(
    name = "org_golang_x_crypto",
    importpath = "golang.org/x/crypto",
    sum = "h1:ypSNr+bnYL2YhwoMt2zPxHFmbAN1KZs/njMG3hxUp30=",
    version = "v0.25.0",
)

go_repository(
    name = "org_golang_x_lint",
    importpath = "golang.org/x/lint",
    sum = "h1:Wh+f8QHJXR411sJR8/vRBTZ7YapZaRvUcLFFJhusH0k=",
    version = "v0.0.0-20200302205851-738671d3881b",
)

go_repository(
    name = "org_golang_x_text",
    importpath = "golang.org/x/text",
    sum = "h1:a94ExnEXNtEwYLGJSIUxnWoxoRz/ZcCsV63ROupILh4=",
    version = "v0.16.0",
)

go_repository(
    name = "org_golang_x_xerrors",
    importpath = "golang.org/x/xerrors",
    sum = "h1:go1bK/D/BFZV2I8cIQd1NKEZ+0owSTG1fDTci4IqFcE=",
    version = "v0.0.0-20200804184101-5ec99f83aff1",
)

go_repository(
    name = "co_honnef_go_tools",
    importpath = "honnef.co/go/tools",
    sum = "h1:/hemPrYIhOhy8zYrNj+069zDB68us2sMGsfkFJO0iZs=",
    version = "v0.0.0-20190523083050-ea95bdfd59fc",
)

go_repository(
    name = "com_github_ajstarks_svgo",
    importpath = "github.com/ajstarks/svgo",
    sum = "h1:wVe6/Ea46ZMeNkQjjBW6xcqyQA/j5e0D6GytH95g0gQ=",
    version = "v0.0.0-20180226025133-644b8db467af",
)

go_repository(
    name = "com_github_apache_arrow_go_arrow",
    importpath = "github.com/apache/arrow/go/arrow",
    sum = "h1:zvQ6w7KwtQWgMQiewOF9tFtundRMVZFSAksNV6ogzuY=",
    version = "v0.0.0-20201229220542-30ce2eb5d4dc",
)

go_repository(
    name = "com_github_awalterschulze_gographviz",
    importpath = "github.com/awalterschulze/gographviz",
    sum = "h1:+cdNqtOJWjvepyhxy23G7z7vmpYCoC65AP0nqi1f53s=",
    version = "v0.0.0-20190522210029-fa59802746ab",
)

go_repository(
    name = "com_github_burntsushi_toml",
    importpath = "github.com/BurntSushi/toml",
    sum = "h1:WXkYYl6Yr3qBf1K79EBnL4mak0OimBfB0XUf9Vl28OQ=",
    version = "v0.3.1",
)

go_repository(
    name = "com_github_census_instrumentation_opencensus_proto",
    importpath = "github.com/census-instrumentation/opencensus-proto",
    sum = "h1:glEXhBS5PSLLv4IXzLA5yPRVX4bilULVyxxbrfOtDAk=",
    version = "v0.2.1",
)

go_repository(
    name = "com_github_chewxy_hm",
    importpath = "github.com/chewxy/hm",
    sum = "h1:zy/TSv3LV2nD3dwUEQL2VhXeoXbb9QkpmdRAVUFiA6k=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_chewxy_math32",
    importpath = "github.com/chewxy/math32",
    sum = "h1:fU5E4Ec4Z+5RtRAi3TovSxUjQPkgRh+HbP7tKB2OFbM=",
    version = "v1.0.8",
)

go_repository(
    name = "com_github_client9_misspell",
    importpath = "github.com/client9/misspell",
    sum = "h1:ta993UF76GwbvJcIo3Y68y/M3WxlpEHPWIGDkJYwzJI=",
    version = "v0.3.4",
)

go_repository(
    name = "com_github_cncf_udpa_go",
    importpath = "github.com/cncf/udpa/go",
    sum = "h1:hzAQntlaYRkVSFEfj9OTWlVV1H155FMD8BTKktLv0QI=",
    version = "v0.0.0-20210930031921-04548b0d99d4",
)

go_repository(
    name = "com_github_davecgh_go_spew",
    importpath = "github.com/davecgh/go-spew",
    sum = "h1:vj9j/u1bqnvCEfJOwUhtlOARqs3+rkHYY13jYWTU97c=",
    version = "v1.1.1",
)

go_repository(
    name = "com_github_disintegration_imaging",
    importpath = "github.com/disintegration/imaging",
    sum = "h1:nVPXRUUQ36Z7MNf0O77UzgnOb1mkMMor7lmJMJXc/mA=",
    version = "v1.6.0",
)

go_repository(
    name = "com_github_envoyproxy_go_control_plane",
    importpath = "github.com/envoyproxy/go-control-plane",
    sum = "h1:xvqufLtNVwAhN8NMyWklVgxnWohi+wtMGQMhtxexlm0=",
    version = "v0.10.2-0.20220325020618-49ff273808a1",
)

go_repository(
    name = "com_github_envoyproxy_protoc_gen_validate",
    importpath = "github.com/envoyproxy/protoc-gen-validate",
    sum = "h1:EQciDnbrYxy13PgWoY8AqoxGiPrpgBZ1R8UNe3ddc+A=",
    version = "v0.1.0",
)

go_repository(
    name = "com_github_fogleman_gg",
    importpath = "github.com/fogleman/gg",
    sum = "h1:WXb3TSNmHp2vHoCroCIB1foO/yQ36swABL8aOVeDpgg=",
    version = "v1.2.1-0.20190220221249-0403632d5b90",
)

go_repository(
    name = "com_github_gogo_protobuf",
    importpath = "github.com/gogo/protobuf",
    sum = "h1:Ov1cvc58UF3b5XjBnZv7+opcTcQFZebYjWzi34vdm4Q=",
    version = "v1.3.2",
)

go_repository(
    name = "com_github_golang_freetype",
    importpath = "github.com/golang/freetype",
    sum = "h1:DACJavvAHhabrF08vX0COfcOBJRhZ8lUbR+ZWIs0Y5g=",
    version = "v0.0.0-20170609003504-e2365dfdc4a0",
)

go_repository(
    name = "com_github_golang_glog",
    importpath = "github.com/golang/glog",
    sum = "h1:VKtxabqXZkF25pY9ekfRL6a582T4P37/31XEstQ5p58=",
    version = "v0.0.0-20160126235308-23def4e6c14b",
)

go_repository(
    name = "com_github_golang_mock",
    importpath = "github.com/golang/mock",
    sum = "h1:G5FRp8JnTd7RQH5kemVNlMeyXQAztQ3mOWV95KxsXH8=",
    version = "v1.1.1",
)

go_repository(
    name = "com_github_golang_protobuf",
    importpath = "github.com/golang/protobuf",
    sum = "h1:ROPKBNFfQgOUMifHyP+KYbvpjbdoFNs+aK7DXlji0Tw=",
    version = "v1.5.2",
)

go_repository(
    name = "com_github_gonum_blas",
    importpath = "github.com/gonum/blas",
    sum = "h1:Q0Jsdxl5jbxouNs1TQYt0gxesYMU4VXRbsTlgDloZ50=",
    version = "v0.0.0-20181208220705-f22b278b28ac",
)

go_repository(
    name = "com_github_google_flatbuffers",
    importpath = "github.com/google/flatbuffers",
    sum = "h1:/PtAHvnBY4Kqnx/xCQ3OIV9uYcSFGScBsWI3Oogeh6w=",
    version = "v1.12.0",
)

go_repository(
    name = "com_github_jung_kurt_gofpdf",
    importpath = "github.com/jung-kurt/gofpdf",
    sum = "h1:PJr+ZMXIecYc1Ey2zucXdR73SMBtgjPgwa31099IMv0=",
    version = "v1.0.3-0.20190309125859-24315acbbda5",
)

go_repository(
    name = "com_github_kelseyhightower_envconfig",
    importpath = "github.com/kelseyhightower/envconfig",
    sum = "h1:Im6hONhd3pLkfDFsbRgu68RDNkGF1r3dvMUtDTo2cv8=",
    version = "v1.4.0",
)

go_repository(
    name = "com_github_kisielk_errcheck",
    importpath = "github.com/kisielk/errcheck",
    sum = "h1:e8esj/e4R+SAOwFwN+n3zr0nYeCyeweozKfO23MvHzY=",
    version = "v1.5.0",
)

go_repository(
    name = "com_github_kisielk_gotool",
    importpath = "github.com/kisielk/gotool",
    sum = "h1:AV2c/EiW3KqPNT9ZKl07ehoAGi4C5/01Cfbblndcapg=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_kr_pty",
    importpath = "github.com/kr/pty",
    sum = "h1:VkoXIwSboBpnk99O/KFauAEILuNHv5DVFKZMBN/gUgw=",
    version = "v1.1.1",
)

go_repository(
    name = "com_github_leesper_go_rng",
    importpath = "github.com/leesper/go_rng",
    sum = "h1:X/79QL0b4YJVO5+OsPH9rF2u428CIrGL/jLmPsoOQQ4=",
    version = "v0.0.0-20190531154944-a612b043e353",
)

go_repository(
    name = "com_github_mattn_go_runewidth",
    importpath = "github.com/mattn/go-runewidth",
    sum = "h1:2BvfKmzob6Bmd4YsL0zygOqfdFnK7GR4QL06Do4/p7Y=",
    version = "v0.0.4",
)

go_repository(
    name = "com_github_miekg_dns",
    importpath = "github.com/miekg/dns",
    sum = "h1:cN8OuEF1/x5Rq6Np+h1epln8OiyPWV+lROx9LxcGgIQ=",
    version = "v1.1.62",
)

go_repository(
    name = "com_github_nfnt_resize",
    importpath = "github.com/nfnt/resize",
    sum = "h1:zYyBkD/k9seD2A7fsi6Oo2LfFZAehjjQMERAvZLEDnQ=",
    version = "v0.0.0-20180221191011-83c6a9932646",
)

go_repository(
    name = "com_github_owulveryck_onnx_go",
    importpath = "github.com/owulveryck/onnx-go",
    sum = "h1:dnSKdTVs8gCbI3MUu91J74YjnYQTDEjoQluN0+/brSg=",
    version = "v0.5.0",
)

go_repository(
    name = "com_github_pkg_errors",
    importpath = "github.com/pkg/errors",
    sum = "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=",
    version = "v0.9.1",
)

go_repository(
    name = "com_github_pmezard_go_difflib",
    importpath = "github.com/pmezard/go-difflib",
    sum = "h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_prometheus_client_model",
    importpath = "github.com/prometheus/client_model",
    sum = "h1:gQz4mCbXsO+nc9n1hCxHcGA3Zx3Eo+UHZoInFGUIXNM=",
    version = "v0.0.0-20190812154241-14fe0d1b01d4",
)

go_repository(
    name = "com_github_sanity_io_litter",
    importpath = "github.com/sanity-io/litter",
    sum = "h1:BllcKWa3VbZmOZbDCoszYLk7zCsKHz5Beossi8SUcTc=",
    version = "v1.1.0",
)

go_repository(
    name = "com_github_stretchr_objx",
    importpath = "github.com/stretchr/objx",
    sum = "h1:4G4v2dO3VZwixGIRoQ5Lfboy6nUhCyYzaqnIAPPhYs4=",
    version = "v0.1.0",
)

go_repository(
    name = "com_github_stretchr_testify",
    importpath = "github.com/stretchr/testify",
    sum = "h1:5TQK59W5E3v0r2duFAb7P95B6hEeOyEnHRa8MjYSMTY=",
    version = "v1.7.1",
)

go_repository(
    name = "com_github_vincent_petithory_dataurl",
    importpath = "github.com/vincent-petithory/dataurl",
    sum = "h1:lyL3z7vYwTWXf4/bI+A01+cCSnfhKIBhy+SQ46Z/ml8=",
    version = "v0.0.0-20160330182126-9a301d65acbb",
)

go_repository(
    name = "com_github_xtgo_set",
    importpath = "github.com/xtgo/set",
    sum = "h1:6BCNBRv3ORNDQ7fyoJXRv+tstJz3m1JVFQErfeZz2pY=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_yuin_goldmark",
    importpath = "github.com/yuin/goldmark",
    sum = "h1:fVcFKWvrslecOb/tg+Cc05dkeYx540o0FuFt3nUVDoE=",
    version = "v1.4.13",
)

go_repository(
    name = "com_google_cloud_go",
    importpath = "cloud.google.com/go",
    sum = "h1:eOI3/cP2VTU6uZLDYAoic+eyzzB9YyGmJ7eIjl8rOPg=",
    version = "v0.34.0",
)

go_repository(
    name = "in_gopkg_check_v1",
    importpath = "gopkg.in/check.v1",
    sum = "h1:YR8cESwS4TdDjEe65xsg0ogRM/Nc3DYOhEAlW+xobZo=",
    version = "v1.0.0-20190902080502-41f04d3bba15",
)

go_repository(
    name = "in_gopkg_cheggaaa_pb_v1",
    importpath = "gopkg.in/cheggaaa/pb.v1",
    sum = "h1:kJdccidYzt3CaHD1crCFTS1hxyhSi059NhOFUf03YFo=",
    version = "v1.0.27",
)

go_repository(
    name = "in_gopkg_yaml_v2",
    importpath = "gopkg.in/yaml.v2",
    sum = "h1:obN1ZagJSUGI0Ek/LBmuj4SNLPfIny3KsKFopxRdj10=",
    version = "v2.2.8",
)

go_repository(
    name = "in_gopkg_yaml_v3",
    importpath = "gopkg.in/yaml.v3",
    sum = "h1:h8qDotaEPuJATrMmW04NCwg7v22aHH28wwpauUhK9Oo=",
    version = "v3.0.0-20210107192922-496545a6307b",
)

go_repository(
    name = "io_rsc_pdf",
    importpath = "rsc.io/pdf",
    sum = "h1:k1MczvYDUvJBe93bYd7wrZLLUEcLZAuF824/I4e5Xr4=",
    version = "v0.1.1",
)

go_repository(
    name = "org_go4_unsafe_assume_no_moving_gc",
    importpath = "go4.org/unsafe/assume-no-moving-gc",
    sum = "h1:FyBZqvoA/jbNzuAWLQE2kG820zMAkcilx6BMjGbL/E4=",
    version = "v0.0.0-20220617031537-928513b29760",
)

go_repository(
    name = "org_golang_google_appengine",
    importpath = "google.golang.org/appengine",
    sum = "h1:/wp5JvzpHIxhs/dumFmF7BXTf3Z+dd4uXta4kVyO508=",
    version = "v1.4.0",
)

go_repository(
    name = "org_golang_google_genproto",
    importpath = "google.golang.org/genproto",
    sum = "h1:DJUvgAPiJWeMBiT+RzBVcJGQN7bAEWS5UEoMshES9xs=",
    version = "v0.0.0-20220503193339-ba3ae3f07e29",
)

go_repository(
    name = "org_golang_google_grpc",
    importpath = "google.golang.org/grpc",
    sum = "h1:oCjezcn6g6A75TGoKYBPgKmVBLexhYLM6MebdrPApP8=",
    version = "v1.46.0",
)

go_repository(
    name = "org_golang_google_grpc_cmd_protoc_gen_go_grpc",
    importpath = "google.golang.org/grpc/cmd/protoc-gen-go-grpc",
    sum = "h1:MZjUhWVLZHiPPNKvwdt31HZVHrASfgk1ScV3vVTKbDo=",
    version = "v0.0.0-20200910201057-6591123024b3",
)

go_repository(
    name = "org_golang_google_protobuf",
    importpath = "google.golang.org/protobuf",
    sum = "h1:w43yiav+6bVFTBQFZX0r7ipe9JQ1QsbMgHwbBziscLw=",
    version = "v1.28.0",
)

go_repository(
    name = "org_golang_x_image",
    importpath = "golang.org/x/image",
    sum = "h1:00VmoueYNlNz/aHIilyyQz/MHSqGoWJzpFv/HW8xpzI=",
    version = "v0.0.0-20180708004352-c73c2afc3b81",
)

go_repository(
    name = "org_golang_x_oauth2",
    importpath = "golang.org/x/oauth2",
    sum = "h1:TzXSXBo42m9gQenoE3b9BGiEpg5IG2JkU5FkPIawgtw=",
    version = "v0.0.0-20200107190931-bf48bf16ab8d",
)

go_repository(
    name = "org_golang_x_telemetry",
    importpath = "golang.org/x/telemetry",
    sum = "h1:zf5N6UOrA487eEFacMePxjXAJctxKmyjKUsjA11Uzuk=",
    version = "v0.0.0-20240521205824-bda55230c457",
)

go_repository(
    name = "org_golang_x_term",
    importpath = "golang.org/x/term",
    sum = "h1:BbsgPEJULsl2fV/AT3v15Mjva5yXKQDyKf+TbDz7QJk=",
    version = "v0.22.0",
)

go_repository(
    name = "org_gonum_v1_gonum",
    importpath = "gonum.org/v1/gonum",
    sum = "h1:CCXrcPKiGGotvnN6jfUsKk4rRqm7q09/YbKb5xCEvtM=",
    version = "v0.8.2",
)

go_repository(
    name = "org_gonum_v1_netlib",
    importpath = "gonum.org/v1/netlib",
    sum = "h1:OE9mWmgKkjJyEmDAAtGMPjXu+YNeGvK9VTSHY6+Qihc=",
    version = "v0.0.0-20190313105609-8cb42192e0e0",
)

go_repository(
    name = "org_gonum_v1_plot",
    importpath = "gonum.org/v1/plot",
    sum = "h1:Qh4dB5D/WpoUUp3lSod7qgoyEHbDGPUWjIbnqdqqe1k=",
    version = "v0.0.0-20190515093506-e2840ee46a6b",
)

go_repository(
    name = "org_gorgonia_cu",
    importpath = "gorgonia.org/cu",
    sum = "h1:s4WQ6fiAGoErwIiXWHRB6Y9ydkx1vTTPwhWzoEZVePc=",
    version = "v0.9.0-beta",
)

go_repository(
    name = "org_gorgonia_dawson",
    importpath = "gorgonia.org/dawson",
    sum = "h1:o7+eJ3SKi9sheH19lpOat//tDbg0Y+M9iY/lH79VHqY=",
    version = "v1.1.0",
)

go_repository(
    name = "org_gorgonia_gorgonia",
    importpath = "gorgonia.org/gorgonia",
    sum = "h1:msE583U+EuthijznpLPJ1Uk6LbNqZCWX/5mgq/L/EGg=",
    version = "v0.9.4",
)

go_repository(
    name = "org_gorgonia_tensor",
    importpath = "gorgonia.org/tensor",
    sum = "h1:8ahrfwO4iby+1ILObIqfjJa+wyA2RoCfJSS3LVERSRE=",
    version = "v0.9.24",
)

go_repository(
    name = "org_gorgonia_vecf32",
    importpath = "gorgonia.org/vecf32",
    sum = "h1:PClazic1r+JVJ1dEzRXgeiVl4g1/Hf/w+wUSqnco1Xg=",
    version = "v0.9.0",
)

go_repository(
    name = "org_gorgonia_vecf64",
    importpath = "gorgonia.org/vecf64",
    sum = "h1:bgZDP5x0OzBF64PjMGC3EvTdOoMEcmfAh1VCUnZFm1A=",
    version = "v0.9.0",
)

go_repository(
    name = "com_github_actgardner_gogen_avro_v10",
    importpath = "github.com/actgardner/gogen-avro/v10",
    sum = "h1:z3pOGblRjAJCYpkIJ8CmbMJdksi4rAhaygw0dyXZ930=",
    version = "v10.2.1",
)

go_repository(
    name = "com_github_actgardner_gogen_avro_v9",
    importpath = "github.com/actgardner/gogen-avro/v9",
    sum = "h1:YZ5tCwV5xnDZrG4uRDQYT2VAWZCRAG3eyQH/WYR2T6Q=",
    version = "v9.1.0",
)

go_repository(
    name = "com_github_antihax_optional",
    importpath = "github.com/antihax/optional",
    sum = "h1:xK2lYat7ZLaVVcIuj82J8kIro4V6kDe0AUDFboUCwcg=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_cespare_xxhash_v2",
    importpath = "github.com/cespare/xxhash/v2",
    sum = "h1:6MnRN8NT7+YBpUIWxHtefFZOKTAPgGjpQSxqLNn0+qY=",
    version = "v2.1.1",
)

go_repository(
    name = "com_github_chzyer_logex",
    importpath = "github.com/chzyer/logex",
    sum = "h1:Swpa1K6QvQznwJRcfTfQJmTE72DqScAa40E+fbHEXEE=",
    version = "v1.1.10",
)

go_repository(
    name = "com_github_chzyer_readline",
    importpath = "github.com/chzyer/readline",
    sum = "h1:fY5BOSpyZCqRo5OhCuC+XN+r/bBCmeuuJtjz+bCNIf8=",
    version = "v0.0.0-20180603132655-2972be24d48e",
)

go_repository(
    name = "com_github_chzyer_test",
    importpath = "github.com/chzyer/test",
    sum = "h1:q763qf9huN11kDQavWsoZXJNW3xEE4JJyHa5Q25/sd8=",
    version = "v0.0.0-20180213035817-a1ea475d72b1",
)

go_repository(
    name = "com_github_cncf_xds_go",
    importpath = "github.com/cncf/xds/go",
    sum = "h1:zH8ljVhhq7yC0MIeUL/IviMtY8hx2mK8cN9wEYb8ggw=",
    version = "v0.0.0-20211011173535-cb28da3451f1",
)

go_repository(
    name = "com_github_confluentinc_confluent_kafka_go",
    importpath = "github.com/confluentinc/confluent-kafka-go",
    sum = "h1:gV/GxhMBUb03tFWkN+7kdhg+zf+QUM+wVkI9zwh770Q=",
    version = "v1.9.2",
)

go_repository(
    name = "com_github_creack_pty",
    importpath = "github.com/creack/pty",
    sum = "h1:uDmaGzcdjhF4i/plgjmEsriH11Y0o7RKapEf/LDaM3w=",
    version = "v1.1.9",
)

go_repository(
    name = "com_github_frankban_quicktest",
    importpath = "github.com/frankban/quicktest",
    sum = "h1:+cqqvzZV87b4adx/5ayVOaYZ2CrvM4ejQvUdBzPPUss=",
    version = "v1.14.0",
)

go_repository(
    name = "com_github_ghodss_yaml",
    importpath = "github.com/ghodss/yaml",
    sum = "h1:wQHKEahhL6wmXdzwWG11gIVCkOv05bNOh+Rxn0yngAk=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_golang_snappy",
    importpath = "github.com/golang/snappy",
    sum = "h1:yAGX7huGHXlcLOEtBnF4w7FQwA26wojNCwOYAEhLjQM=",
    version = "v0.0.4",
)

go_repository(
    name = "com_github_google_gofuzz",
    importpath = "github.com/google/gofuzz",
    sum = "h1:A8PeW59pxE9IoFRqBp37U+mSNaQoZ46F1f0f863XSXw=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_google_pprof",
    importpath = "github.com/google/pprof",
    sum = "h1:zHs+jv3LO743/zFGcByu2KmpbliCU2AhjcGgrdTwSG4=",
    version = "v0.0.0-20211008130755-947d60d73cc0",
)

go_repository(
    name = "com_github_google_uuid",
    importpath = "github.com/google/uuid",
    sum = "h1:t6JiXgmwXMjEs8VusXIJk2BXHsn+wx8BZdTaoZ5fu7I=",
    version = "v1.3.0",
)

go_repository(
    name = "com_github_grpc_ecosystem_grpc_gateway",
    importpath = "github.com/grpc-ecosystem/grpc-gateway",
    sum = "h1:gmcG1KaJ57LophUzW0Hy8NmPhnMZb4M0+kPpLofRdBo=",
    version = "v1.16.0",
)

go_repository(
    name = "com_github_hamba_avro",
    importpath = "github.com/hamba/avro",
    sum = "h1:/UBljlJ9hLjkcY7PhpI/bFYb4RMEXHEwHr17gAm/+l8=",
    version = "v1.5.6",
)

go_repository(
    name = "com_github_heetch_avro",
    importpath = "github.com/heetch/avro",
    sum = "h1:i6DyUBDIwzt6Fs78dYBIXYd5XrYUs/ir4+39WbHQhJE=",
    version = "v0.3.1",
)

go_repository(
    name = "com_github_iancoleman_orderedmap",
    importpath = "github.com/iancoleman/orderedmap",
    sum = "h1:i462o439ZjprVSFSZLZxcsoAe592sZB1rci2Z8j4wdk=",
    version = "v0.0.0-20190318233801-ac98e3ecb4b0",
)

go_repository(
    name = "com_github_ianlancetaylor_demangle",
    importpath = "github.com/ianlancetaylor/demangle",
    sum = "h1:uGg2frlt3IcT7kbV6LEp5ONv4vmoO2FW4qSO+my/aoM=",
    version = "v0.0.0-20210905161508-09a460cdf81d",
)

go_repository(
    name = "com_github_invopop_jsonschema",
    importpath = "github.com/invopop/jsonschema",
    sum = "h1:Yuy/unfgCnfV5Wl7H0HgFufp/rlurqPOOuacqyByrws=",
    version = "v0.4.0",
)

go_repository(
    name = "com_github_jhump_gopoet",
    importpath = "github.com/jhump/gopoet",
    sum = "h1:gYjOPnzHd2nzB37xYQZxj4EIQNpBrBskRqQQ3q4ZgSg=",
    version = "v0.1.0",
)

go_repository(
    name = "com_github_jhump_goprotoc",
    importpath = "github.com/jhump/goprotoc",
    sum = "h1:Y1UgUX+txUznfqcGdDef8ZOVlyQvnV0pKWZH08RmZuo=",
    version = "v0.5.0",
)

go_repository(
    name = "com_github_jhump_protoreflect",
    importpath = "github.com/jhump/protoreflect",
    sum = "h1:1NQ4FpWMgn3by/n1X0fbeKEUxP1wBt7+Oitpv01HR10=",
    version = "v1.12.0",
)

go_repository(
    name = "com_github_json_iterator_go",
    importpath = "github.com/json-iterator/go",
    sum = "h1:uVUAXhF2To8cbw/3xN3pxj6kk7TYKs98NIrTqPlMWAQ=",
    version = "v1.1.11",
)

go_repository(
    name = "com_github_juju_qthttptest",
    importpath = "github.com/juju/qthttptest",
    sum = "h1:JPju5P5CDMCy8jmBJV2wGLjDItUsx2KKL514EfOYueM=",
    version = "v0.1.1",
)

go_repository(
    name = "com_github_julienschmidt_httprouter",
    importpath = "github.com/julienschmidt/httprouter",
    sum = "h1:U0609e9tgbseu3rBINet9P48AI/D3oJs4dN7jwJOQ1U=",
    version = "v1.3.0",
)

go_repository(
    name = "com_github_linkedin_goavro",
    importpath = "github.com/linkedin/goavro",
    sum = "h1:DV2aUlj2xZiuxQyvag8Dy7zjY69ENjS66bWkSfdpddY=",
    version = "v2.1.0+incompatible",
)

go_repository(
    name = "com_github_linkedin_goavro_v2",
    importpath = "github.com/linkedin/goavro/v2",
    sum = "h1:4cuAtbDfqkKnBXp9E+tRkIJGa6W6iAjwonwt8O1f4U0=",
    version = "v2.11.1",
)

go_repository(
    name = "com_github_modern_go_concurrent",
    importpath = "github.com/modern-go/concurrent",
    sum = "h1:TRLaZ9cD/w8PVh93nsPXa1VrQ6jlwL5oN8l14QlcNfg=",
    version = "v0.0.0-20180306012644-bacd9c7ef1dd",
)

go_repository(
    name = "com_github_modern_go_reflect2",
    importpath = "github.com/modern-go/reflect2",
    sum = "h1:9f412s+6RmYXLWZSEzVVgPGK7C2PphHj5RJrvfx9AWI=",
    version = "v1.0.1",
)

go_repository(
    name = "com_github_nrwiersma_avro_benchmarks",
    importpath = "github.com/nrwiersma/avro-benchmarks",
    sum = "h1:wDbc54qVQ+C5oQZ8Q5VlMbqEt2hrnev2bC/gIGL3Ksk=",
    version = "v0.0.0-20210913175520-21aec48c8f76",
)

go_repository(
    name = "com_github_pkg_diff",
    importpath = "github.com/pkg/diff",
    sum = "h1:aoZm08cpOy4WuID//EZDgcC4zIxODThtZNPirFr42+A=",
    version = "v0.0.0-20210226163009-20ebb0f2a09e",
)

go_repository(
    name = "com_github_rogpeppe_clock",
    importpath = "github.com/rogpeppe/clock",
    sum = "h1:3QH7VyOaaiUHNrA9Se4YQIRkDTCw1EJls9xTUCaCeRM=",
    version = "v0.0.0-20190514195947-2896927a307a",
)

go_repository(
    name = "com_github_rogpeppe_fastuuid",
    importpath = "github.com/rogpeppe/fastuuid",
    sum = "h1:Ppwyp6VYCF1nvBTXL3trRso7mXMlRrw9ooo375wvi2s=",
    version = "v1.2.0",
)

go_repository(
    name = "com_github_santhosh_tekuri_jsonschema_v5",
    importpath = "github.com/santhosh-tekuri/jsonschema/v5",
    sum = "h1:TToq11gyfNlrMFZiYujSekIsPd9AmsA2Bj/iv+s4JHE=",
    version = "v5.0.0",
)

go_repository(
    name = "in_gopkg_avro_v0",
    importpath = "gopkg.in/avro.v0",
    sum = "h1:PGIdqvwfpMUyUP+QAlAnKTSWQ671SmYjoou2/5j7HXk=",
    version = "v0.0.0-20171217001914-a730b5802183",
)

go_repository(
    name = "in_gopkg_errgo_v1",
    importpath = "gopkg.in/errgo.v1",
    sum = "h1:n+7XfCyygBFb8sEjg6692xjC6Us50TFRO54+xYUEwjE=",
    version = "v1.0.0",
)

go_repository(
    name = "in_gopkg_errgo_v2",
    importpath = "gopkg.in/errgo.v2",
    sum = "h1:0vLT13EuvQ0hNvakwLuFZ/jYrLp5F3kcWHXdRggjCE8=",
    version = "v2.1.0",
)

go_repository(
    name = "in_gopkg_httprequest_v1",
    importpath = "gopkg.in/httprequest.v1",
    sum = "h1:pEPLMdF/gjWHnKxLpuCYaHFjc8vAB2wrYjXrqDVC16E=",
    version = "v1.2.1",
)

go_repository(
    name = "in_gopkg_mgo_v2",
    importpath = "gopkg.in/mgo.v2",
    sum = "h1:VpOs+IwYnYBaFnrNAeB8UUWtL3vEUnzSCL1nVjPhqrw=",
    version = "v2.0.0-20190816093944-a6b53ec6cb22",
)

go_repository(
    name = "in_gopkg_retry_v1",
    importpath = "gopkg.in/retry.v1",
    sum = "h1:a9CArYczAVv6Qs6VGoLMio99GEs7kY9UzSF9+LD+iGs=",
    version = "v1.0.3",
)

go_repository(
    name = "io_opentelemetry_go_proto_otlp",
    importpath = "go.opentelemetry.io/proto/otlp",
    sum = "h1:rwOQPCuKAKmwGKq2aVNnYIibI6wnV7EvzgfTCzcdGg8=",
    version = "v0.7.0",
)

# gazelle:repository_macro deps.bzl%go_dependencies
go_dependencies()

go_rules_dependencies()

go_register_toolchains(version = "1.22.3")

gazelle_dependencies()
# go_dependencies()
