variable "COMMIT_SHA" {
    default = null
    validation {
        condition = COMMIT_SHA != ""
        error_message = "No `COMMIT_SHA`."
    }
}

variable "PLUGIN_NAME" {
    default = ""
    validation {
        condition = PLUGIN_NAME != ""
        error_message = "No plugin."
    }
}

variable USE_CACHE {
    default = 0
}

variable "IMAGE_BASE_NAME" {
    default = "092457480553.dkr.ecr.us-west-2.amazonaws.com/eth-monitoring"
}

group "default" {
    targets = PLUGIN_NAME == "aavev3" ? ["geth", "dashboard"] : ["geth"]
}

target "common" {
    platforms = ["linux/arm64"]
    args = {
        PLUGIN_NAME = "${PLUGIN_NAME}"
    }
}

target "geth" {
    inherits = ["common"]

    target = "geth"
    cache-from = [
        USE_CACHE > 0 ? "type=registry,ref=${IMAGE_BASE_NAME}:buildcache" : "",
    ]
    cache-to = [
        USE_CACHE > 0 ? "type=registry,ref=${IMAGE_BASE_NAME}:buildcache,image-manifest=true,mode=min,oci-mediatypes=true,compression=zstd" : "",
    ]
    tags = [
       "${IMAGE_BASE_NAME}:${COMMIT_SHA}-${PLUGIN_NAME}",
       "${IMAGE_BASE_NAME}:latest-${PLUGIN_NAME}",
    ]
}

target "dashboard" {
    inherits = ["common"]

    target = "dashboard"
    cache-from = [
        USE_CACHE > 0 ?  "type=registry,ref=${IMAGE_BASE_NAME}:dashboard-buildcache" : "",
    ]
    cache-to = [
       USE_CACHE > 0 ?  "type=registry,ref=${IMAGE_BASE_NAME}:dashboard-buildcache,image-manifest=true,mode=max,oci-mediatypes=true,compression=zstd" : "",
    ]
    tags = [
       "${IMAGE_BASE_NAME}:${COMMIT_SHA}-${PLUGIN_NAME}-dashboard",
       "${IMAGE_BASE_NAME}:latest-${PLUGIN_NAME}-dashboard"
    ]
}

