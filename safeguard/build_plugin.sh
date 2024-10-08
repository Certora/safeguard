set -x

cd $(cd $(dirname $0); realpath .)
TS=$(date +%s)

if [ -z $1 ]; then
    echo "No plugin name specified quitting"
    exit 1
fi

PLUGIN_PATH=plugin_build/safeguard_$TS

mkdir ./plugin_build/safeguard_$TS
cp -r ./$1/* ./plugin_build/safeguard_$TS

GO=go
if [ $GO_BIN ]; then
    GO=$GO_BIN
fi


output=safeguard.so
PLUGIN_OBJ=$(realpath $PLUGIN_PATH/$output)
if [ $SAFEGUARD_OBJ_PATH ]; then
    output=$SAFEGUARD_OBJ_PATH
    PLUGIN_OBJ=$output
fi


head_hash=$(git rev-parse HEAD)
commit_date=$(git show -s --format=%ci "$head_hash" | cut -d ' ' -f 1 | sed 's/-//g')

(cd $PLUGIN_PATH; GOMODCACHE=/tmp/go-cache $GO build -ldflags "-X github.com/ethereum/go-ethereum/internal/version.gitCommit=$head_hash -X github.com/ethereum/go-ethereum/internal/version.gitDate=$commit_date -extldflags '-Wl,-z,stack-size=0x800000'" -tags urfave_cli_no_docs,ckzg -buildmode=plugin -trimpath -v  -o $output .)

if [ $? -ne 0 ]; then
    echo "Build failed, not trying to redeploy"
    exit 1
fi

if [ $SAFEGUARD_MODE = "SIGNAL" ]; then
    pid=$(pgrep -f "geth")

    # Check if the process is found
    if [ -z "$pid" ]; then
        echo "No geth process found."
        exit 1
    fi
    if [ -z $SAFEGUARD_PLUGIN_PATH ]; then
        echo "Plugin path not set, not redeploying"
        exit 1
    fi
    rm -f $SAFEGUARD_PLUGIN_PATH
    ln -s $PLUGIN_OBJ $SAFEGUARD_PLUGIN_PATH
    kill -SIGUSR1 $pid;
elif [ $SAFEGUARD_MODE = "SOCKET" ]; then
    if [ -z $SAFEGUARD_SOCKET_PATH ]; then
        echo "Admin socket path not set, not redeploying"
        exit 1
    fi
    echo "{\"type\":\"RELOAD\",\"data\":\"$PLUGIN_OBJ\"}" | socat - UNIX-CONNECT:$SAFEGUARD_SOCKET_PATH
else
    echo "Not trying to reload"
fi

echo "Done"
exit 0;
