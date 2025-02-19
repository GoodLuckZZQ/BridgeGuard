# Install python3

# Install dependencies
# 1 pip3 install solc-select 
# 2 pip3 install z3-solver==4.10.2.0
# 3 Install golang
    brew install golang
    https://golang.google.cn/doc/install

    path：vim ~/.bashrc
    export GOROOT=/usr/local/go
    export GOPATH=$PATH:$GOROOT/bin
    source  ~/.bashrc
# 4 Install geth
    git clone https://github.com/ethereum/go-ethereum.git
    cd go-ethereum
    make all
    ln -s /Users/../go-ethereum/build/bin/geth /usr/local/bin/geth
    ln -s /Users/../go-ethereum/build/bin/evm /usr/local/bin/evm


# Analyze mutiple files: python3 BridgeGuard.py -js curated/L1Bridge/
# Analyze runtime code: python3 BridgeGuard.py -bs 0_examples/test.bin-runtime
# Analyze solidity source code: python3 BridgeGuard.py -sol 0_examples/test.sol 


