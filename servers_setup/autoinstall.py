import os, argparse
import subprocess

current_folder = os.path.dirname(os.path.abspath(__file__))
os.chdir(current_folder)

def install_caddy(version):
    if version=='2.4.6':
        os.system("rm -r ./caddy-2.4.6; mkdir caddy-2.4.6")
        os.chdir("caddy-2.4.6")
        os.system("cp ../caddy-files/v2.4.6/caddy ./")
        os.system("cp ../caddy-files/v2.4.6/Caddyfile ./")
        os.system("sudo ./caddy run")
    if version=='2.7.6':
        os.system("rm -rf ./caddy-2.7.6; mkdir caddy-2.7.6")
        os.chdir("caddy-2.7.6")
        os.system("cp ../caddy-files/v2.7.6/caddy ./")
        os.system("cp ../caddy-files/v2.7.6/Caddyfile ./")
        os.system("chmod +x ./*")
        os.system("sudo ./caddy run")
    if version=='2.8.4':
        os.system("rm -rf ./caddy-2.8.4; mkdir caddy-2.8.4")
        os.chdir("caddy-2.8.4")
        os.system("cp ../caddy-files/v2.8.4/caddy ./")
        os.system("cp ../caddy-files/v2.8.4/Caddyfile ./")
        os.system("chmod +x ./*")
        os.system("sudo ./caddy run")
    if version=='2.10.0':
        os.system("rm -rf ./caddy-2.10.0; mkdir caddy-2.10.0")
        os.chdir("caddy-2.10.0")
        os.system("cp ../caddy-files/v2.10.0/caddy ./")
        os.system("cp ../caddy-files/v2.10.0/Caddyfile ./")
        os.system("chmod +x ./*")
        os.system("sudo ./caddy run")

def install_nginx(version):
    if version=='1.23.4':
        os.system("sudo apt update && sudo apt install -y build-essential")
        os.system("sudo rm -r ./nginx-quic")
        os.system("rm nginx-quic.tar.gz")
        
        os.system("cp ../nginx-files/v1.23.4/nginx-quic.tar.gz ./")
        os.system("tar -zxf nginx-quic.tar.gz")
        os.chdir("nginx-quic")
        
        # os.system("mkdir ./installation-root")
        
        os.system("./auto/configure --with-debug --with-http_v3_module         \
					   --prefix=./installation-root \
                       --with-cc-opt=\"-I./boringssl/include\"     \
                       --with-ld-opt=\"-L./boringssl/build/ssl    \
                                      -L./boringssl/build/crypto\"")        
        os.system("sudo make -j")
        os.system("sudo make install")
        os.system("sudo cp ../nginx-files/nginx.conf ./installation-root/conf/nginx.conf")

        os.system("sudo ./installation-root/sbin/nginx")
        

    elif version=='1.25.5':
        os.system("sudo apt update && sudo apt install -y build-essential gcc libpcre3-dev libssl-dev zlib1g-dev")
        os.system("rm -rf ./nginx-1.25.5")
        os.system("rm ./nginx-1.25.5.tar.gz")

        os.system("wget https://github.com/nginx/nginx/releases/download/release-1.25.5/nginx-1.25.5.tar.gz")
        os.system("tar -zxf nginx-1.25.5.tar.gz")
        os.chdir("nginx-1.25.5")
        os.system('./configure \
	--prefix=./installation-root \
	--with-debug \
	--with-http_v3_module \
	--with-cc-opt="-I./boringssl/include" \
	--with-ld-opt="-L./boringssl/build/ssl -L../boringssl/build/crypto"')
        os.system("sudo make -j")
        os.system("sudo make install")
        os.system("sudo cp ../nginx-files/nginx.conf ./installation-root/conf/nginx.conf")
        os.system("sudo ./installation-root/sbin/nginx")


    elif version=='1.27.0':
        os.system("sudo apt update && sudo apt install -y build-essential gcc libpcre3-dev libssl-dev zlib1g-dev")
        os.system("rm -rf ./nginx-1.27.0")
        os.system("rm ./nginx-1.27.0.tar.gz")
        
        os.system("wget https://github.com/nginx/nginx/releases/download/release-1.27.0/nginx-1.27.0.tar.gz")
        os.system("tar -zxf nginx-1.27.0.tar.gz")
        os.chdir("nginx-1.27.0")
        os.system('./configure \
	--prefix=./installation-root \
	--with-debug \
	--with-http_v3_module \
	--with-cc-opt="-I./boringssl/include" \
	--with-ld-opt="-L./boringssl/build/ssl -L../boringssl/build/crypto"')
        os.system("sudo make -j")
        os.system("sudo make install")
        os.system("sudo cp ../nginx-files/nginx.conf ./installation-root/conf/nginx.conf")
        os.system("sudo ./installation-root/sbin/nginx")


    elif version=='1.28.0':
        os.system("sudo apt update && sudo apt install -y build-essential gcc libpcre3-dev libssl-dev zlib1g-dev")
        os.system("rm -rf ./nginx-1.28.0")
        os.system("rm ./nginx-1.28.0.tar.gz")
        
        os.system("wget https://github.com/nginx/nginx/releases/download/release-1.28.0/nginx-1.28.0.tar.gz")
        os.system("tar -zxf nginx-1.28.0.tar.gz")
        os.chdir("nginx-1.28.0")
        os.system('./configure \
	--prefix=./installation-root \
	--with-debug \
	--with-http_v3_module \
	--with-cc-opt="-I./boringssl/include" \
	--with-ld-opt="-L./boringssl/build/ssl -L./boringssl/build/crypto"')

        os.system("sudo make -j2")
        os.system("sudo make install")
        os.system("sudo cp ../nginx-files/nginx.conf ./installation-root/conf/nginx.conf")
        os.system("sudo ./installation-root/sbin/nginx")

def install_openlitespeed(version):
    if version=='1.7.15':
        os.system("sudo rm -r ./ols-1.7.15 /usr/local/lsws/; mkdir ./ols-1.7.15")
        os.chdir("ols-1.7.15")
        os.system("cp ../ols-files/openlitespeed-1.7.15.tgz ./")
        os.system("tar -zxf openlitespeed-1.7.15.tgz")
        os.chdir("openlitespeed")
        os.system("sudo bash install.sh")

        os.system("sudo cp ../../ols-files/httpd_config.conf /usr/local/lsws/conf/httpd_config.conf")
        # Configuration with relative path to the SSL certs didn't work. Put absolute path.
        os.system("sudo sed -i -e s+SSL_CERT_PATH+{}/certs/prett3.com.crt+g /usr/local/lsws/conf/httpd_config.conf".format(current_folder))
        os.system("sudo sed -i -e s+SSL_KEY_PATH+{}/certs/prett3.com.key+g /usr/local/lsws/conf/httpd_config.conf".format(current_folder))
        
        # Update chconf.conf
        os.system("sudo cp ../../ols-files/vhconf.conf /usr/local/lsws/conf/vhosts/Example/vhconf.conf")
        os.system("sudo sed -i -e s+'$VH_ROOT/html/'+/usr/local/nginx/html/+g /usr/local/lsws/conf/vhosts/Example/vhconf.conf")
        os.system("sudo sed -i -e s+VERSION+LiteSpeed\ {}+g /usr/local/lsws/conf/vhosts/Example/vhconf.conf".format(version))

        os.system("sudo /usr/local/lsws/bin/lswsctrl start")

    elif version=='1.8.1':
        os.system("sudo rm -r ./ols-1.8.1 /usr/local/lsws/; mkdir ./ols-1.8.1")
        os.chdir("ols-1.8.1")
        os.system("cp ../ols-files/openlitespeed-1.8.1.tgz ./")
        os.system("tar -zxf openlitespeed-1.8.1.tgz")
        os.chdir("openlitespeed")
        os.system("sudo bash install.sh")

        os.system("sudo cp ../../ols-files/httpd_config.conf /usr/local/lsws/conf/httpd_config.conf")
        # Configuration with relative path to the SSL certs didn't work. Put absolute path.
        os.system("sudo sed -i -e s+SSL_CERT_PATH+{}/certs/prett3.com.crt+g /usr/local/lsws/conf/httpd_config.conf".format(current_folder))
        os.system("sudo sed -i -e s+SSL_KEY_PATH+{}/certs/prett3.com.key+g /usr/local/lsws/conf/httpd_config.conf".format(current_folder))
        
        # Update chconf.conf
        os.system("sudo cp ../../ols-files/vhconf.conf /usr/local/lsws/conf/vhosts/Example/vhconf.conf")
        os.system("sudo sed -i -e s+'$VH_ROOT/html/'+/usr/local/nginx/html/+g /usr/local/lsws/conf/vhosts/Example/vhconf.conf")
        os.system("sudo sed -i -e s+VERSION+LiteSpeed\ {}+g /usr/local/lsws/conf/vhosts/Example/vhconf.conf".format(version))

        os.system("sudo /usr/local/lsws/bin/lswsctrl start")

    elif version=='1.8.3.1':
        os.system("sudo rm -r ./ols-1.8.3.1 /usr/local/lsws/; mkdir ./ols-1.8.3.1")
        os.chdir("ols-1.8.3.1")
        os.system("wget https://github.com/litespeedtech/openlitespeed/releases/download/v1.8.3.1/openlitespeed-1.8.3-x86_64-linux.tgz")

        os.system("tar -zxf openlitespeed-1.8.3-x86_64-linux.tgz")
        os.chdir("openlitespeed")
        os.system("sudo bash install.sh")

        os.system("sudo cp ../../ols-files/httpd_config.conf /usr/local/lsws/conf/httpd_config.conf")
        # Configuration with relative path to the SSL certs didn't work. Put absolute path.
        os.system("sudo sed -i -e s+SSL_CERT_PATH+{}/certs/prett3.com.crt+g /usr/local/lsws/conf/httpd_config.conf".format(current_folder))
        os.system("sudo sed -i -e s+SSL_KEY_PATH+{}/certs/prett3.com.key+g /usr/local/lsws/conf/httpd_config.conf".format(current_folder))
        
        # Update chconf.conf
        os.system("sudo cp ../../ols-files/vhconf.conf /usr/local/lsws/conf/vhosts/Example/vhconf.conf")
        os.system("sudo sed -i -e s+'$VH_ROOT/html/'+/usr/local/nginx/html/+g /usr/local/lsws/conf/vhosts/Example/vhconf.conf")
        os.system("sudo sed -i -e s+VERSION+LiteSpeed\ {}+g /usr/local/lsws/conf/vhosts/Example/vhconf.conf".format(version))

        os.system("sudo /usr/local/lsws/bin/lswsctrl start")

def install_h2o(version):
    os.system("sudo apt install -y unzip cmake build-essential libssl-dev zlib1g-dev")
    if version=='a429117': # 2022/02/15
        os.system("sudo rm -r ./h2o-a429117; mkdir ./h2o-a429117")
        os.chdir("h2o-a429117")
        os.system("cp ../h2o-files/a429117/a429117babff09542d3517c4fa36c1ef769889c1.zip ./")
        os.system("unzip a429117babff09542d3517c4fa36c1ef769889c1.zip")
        os.chdir("h2o-a429117babff09542d3517c4fa36c1ef769889c1")
        os.system("mkdir -p build")
        os.chdir("build")
        os.system("cmake ..")
        os.system("make")
        os.system("sudo make install")
        os.system("cp ../../../h2o-files/a429117/h2o.conf ../examples/h2o/h2o.conf")
        os.system("sudo ./h2o -c ../examples/h2o/h2o.conf")
    if version=='222b36d': # 2024/04/11
        os.system("sudo rm -r ./h2o-222b36d; mkdir ./h2o-222b36d")
        os.chdir("h2o-222b36d")
        os.system("cp ../h2o-files/222b36d/222b36d7bd3a98616eae82993552098747268d5e.zip ./")
        os.system("unzip 222b36d7bd3a98616eae82993552098747268d5e.zip")
        os.chdir("h2o-222b36d7bd3a98616eae82993552098747268d5e")
        os.system("mkdir -p build")
        os.chdir("build")
        os.system("cmake ..")
        os.system("make")
        os.system("sudo make install")
        os.system("cp ../../../h2o-files/222b36d/h2o.conf ../examples/h2o/h2o.conf")
        os.system("sudo ./h2o -c ../examples/h2o/h2o.conf")
    if version=='16b13ee': # 2024/06/18
        os.system("sudo rm -r ./h2o-16b13ee; mkdir ./h2o-16b13ee")
        os.chdir("h2o-16b13ee")
        os.system("cp ../h2o-files/16b13ee/16b13eee8ad7895b4fe3fcbcabee53bd52782562.zip ./")
        os.system("unzip 16b13eee8ad7895b4fe3fcbcabee53bd52782562.zip")
        os.chdir("h2o-16b13eee8ad7895b4fe3fcbcabee53bd52782562")
        os.system("mkdir -p build")
        os.chdir("build")
        os.system("cmake ..")
        os.system("make")
        os.system("sudo make install")
        os.system("cp ../../../h2o-files/16b13ee/h2o.conf ../examples/h2o/h2o.conf")
        os.system("sudo ./h2o -c ../examples/h2o/h2o.conf")
    if version=="f1918a5": # 2025/04/29
        os.system("sudo rm -rf ./h2o-f1918a5; mkdir ./h2o-f1918a5")
        os.system("git clone https://github.com/h2o/h2o.git ./h2o-f1918a5")
        os.chdir("h2o-f1918a5")
        os.system("git checkout f1918a5b9f75f4da9db801b442886cb13b3c7bcd")
        os.system("mkdir -p build")
        os.chdir("build")
        os.system("cmake ..")
        os.system("make")
        os.system("sudo make install")
        os.system("cp ../../h2o-files/f1918a5/h2o.conf ../examples/h2o/h2o.conf")
        os.system("cp /usr/local/nginx/html/index.html ../examples/doc_root/index.html") # replace the html file
        os.system("sudo ./h2o -c ../examples/h2o/h2o.conf")
    
    
def install_quiche(version):
    if version == '0.23.5':
        os.system("sudo rm -r ./quiche")

        # install dependencies: rust and cmake
        os.system("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sudo sh -s -- -y") 
        os.system("sudo apt install -y build-essential cmake")
        
        # clone Quiche
        os.system("git clone https://github.com/cloudflare/quiche.git")
        os.chdir("quiche")
        os.system("git checkout tags/0.23.5")
        os.system("git submodule update --init --recursive") # retrieve submodules, such as boringssl

        # build and run
        os.system("sudo env RUSTFLAGS=\"-C link-args=-lstdc++\" /root/.cargo/bin/cargo run --release --bin quiche-server -- --listen 0.0.0.0:443 --cert ../certs/prett3.com.crt --key ../certs/prett3.com.key --root /usr/local/nginx/html/ --no-retry --name prett3.com")
        

def install_quic_go(version):
    if version == '0.50.1':
        os.system("sudo rm -r ./quic-go")
        
        # install go https://go.dev/doc/install
        os.system("wget https://go.dev/dl/go1.24.2.linux-amd64.tar.gz")
        os.system("sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.24.2.linux-amd64.tar.gz")
        os.system("sudo rm go1.24.2.linux-amd64.tar.gz")

        # clone Quic-Go
        os.system("git clone https://github.com/quic-go/quic-go.git")
        os.chdir("quic-go")
        os.system("git checkout tags/v0.50.1")

        # run
        os.system("sudo /usr/local/go/bin/go run example/main.go -bind 0.0.0.0:443 -www /usr/local/nginx/html/ -cert ../certs/prett3.com.crt -key ../certs/prett3.com.key")

def install_msquic_kestrel(version):
    if version == '2.4.8':
        os.system("sudo rm -rf ./msquic_kestrel")

        # install msquic library
        os.system("wget -q https://packages.microsoft.com/keys/microsoft.asc -O- | sudo apt-key add -")
        os.system("sudo add-apt-repository -y \"deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-ubuntu-$(lsb_release -cs)-prod $(lsb_release -cs) main\"")
        os.system("sudo apt update")
        # install the latest (2.4.8) libmsquic. Previous versions cause problems https://github.com/dotnet/runtime/issues/105788
        os.system("sudo apt install -y libmsquic=2.4.8")

        # install .NET SDK. msquic needs it https://github.com/microsoft/msquic/blob/main/docs/BUILD.md
        # https://learn.microsoft.com/en-us/dotnet/core/install/linux-ubuntu-install
        os.system("sudo add-apt-repository ppa:dotnet/backports -y")
        os.system("sudo apt update")
        os.system("sudo apt install dotnet-sdk-9.0=9.0.203-1 -y")

        # it is possible that, apt installs dotnet into /usr/share/dotnet/sdk/
        # but dotnet searches for SDKs in /usr/lib/dotnet/sdk/
        os.system("sudo ln -s /usr/share/dotnet/sdk /usr/lib/dotnet/sdk")

        # create and run .NET project
        os.system("dotnet new web -n msquic_kestrel")
        os.chdir("msquic_kestrel")
        os.system("cp ../msquic-kestrel-files/Program.cs ./")
        os.system("sudo dotnet run")

def install_neqo(version):

    # install dependencies
    os.system("sudo apt install -y build-essential zlib1g-dev libnss3-tools mercurial clang gyp ninja-build")

    # Install Rust
    os.system("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y")

    if version == '0.13.1':
        
        os.system("sudo rm -rf ./neqo-0.13.1")
        
        # clone Neqo v0.13.1
        os.system("git clone https://github.com/mozilla/neqo.git ./neqo-0.13.1")
        os.chdir("./neqo-0.13.1")
        os.system("git checkout tags/v0.13.1")

        # create NSS database with our ssl certs
        os.system("mkdir certdb")
        os.system("pk12util -i ../certs/prett3.com.pfx -d ./certdb/ -W \"\" -K \"\"")

        # clone Neqo's dependencies: NSS v3.110 and NSPR v4.36
        os.system("hg clone https://hg.mozilla.org/projects/nss")
        os.system("hg clone https://hg.mozilla.org/projects/nspr")
        # Optionally, you can choose NSS & NSP versions that were released around the release time of the chosen Neqo version
        # os.chdir("nss")
        # os.system("hg update NSS_3_115_RTM")
        # os.chdir("../nspr")
        # os.system("hg update NSPR_4_37_RTM")
        # os.chdir("..")

        # build NSS
        os.system("sudo update-alternatives --install /usr/bin/python python /usr/bin/python3 1")
        os.system("bash ./nss/build.sh")
        
        # set necessary env variables (NSS_DIR and LD_LIBRARY_PATH) and install Neqo
        os.system("export NSS_DIR=\"$(realpath ./nss)\"; export LD_LIBRARY_PATH=\"$(realpath ./dist/Debug/lib)\"; $HOME/.cargo/bin/cargo build --release")

        # run Neqo's test server
        os.system("sudo env LD_LIBRARY_PATH=\"$(realpath ./dist/Debug/lib)\" RUST_BACKTRACE=full ./target/release/neqo-server 0.0.0.0:443 -d ./certdb/ -k \"prett3.com - CUNY\"")


    if version == '0.14.1':
        os.system("sudo rm -rf ./neqo-0.14.1")

        # clone Neqo v0.14.1
        os.system("git clone https://github.com/mozilla/neqo.git ./neqo-0.14.1")
        os.chdir("./neqo-0.14.1")
        os.system("git checkout tags/v0.14.1")

        # create NSS database with our ssl certs
        os.system("mkdir certdb")
        os.system("pk12util -i ../certs/prett3.com.pfx -d ./certdb/ -W \"\" -K \"\"")

        # clone Neqo's dependencies: NSS v3.110 and NSPR v4.36
        os.system("hg clone https://hg.mozilla.org/projects/nss")
        os.system("hg clone https://hg.mozilla.org/projects/nspr")
        # Optionally, you can choose NSS & NSP versions that were released around the release time of the chosen Neqo version
        # os.chdir("nss")
        # os.system("hg update NSS_3_115_RTM")
        # os.chdir("../nspr")
        # os.system("hg update NSPR_4_37_RTM")
        # os.chdir("..")
        
        # build NSS
        os.system("sudo update-alternatives --install /usr/bin/python python /usr/bin/python3 1")
        os.system("bash ./nss/build.sh")
        
        # set necessary env variables (NSS_DIR and LD_LIBRARY_PATH) and install Neqo
        os.system("export NSS_DIR=\"$(realpath ./nss)\"; export LD_LIBRARY_PATH=\"$(realpath ./dist/Debug/lib)\"; $HOME/.cargo/bin/cargo build --release")

        # run Neqo's test server
        os.system("sudo env LD_LIBRARY_PATH=\"$(realpath ./dist/Debug/lib)\" RUST_BACKTRACE=full ./target/release/neqo-server 0.0.0.0:443 -d ./certdb/ -k \"prett3.com - CUNY\"")


def install_aioquic(version):
    if version == '1.2.0':
        os.system("sudo rm -rf ./aioquic")

        # install dependencies
        os.system("sudo apt install -y python3-pip")
        os.system("sudo pip3 install aioquic==1.2.0 wsproto==1.2.0 starlette==0.46.2 jinja2==3.1.6")

        # clone aioquic test server
        os.system("git clone https://github.com/aiortc/aioquic.git")
        os.chdir("aioquic")
        os.system("git checkout tags/1.2.0")
        
        # backup the default index.html and replace with the one we always use
        os.system("cp ./examples/templates/index.html ./examples/templates/index.html.bak")
        os.system("cp /usr/local/nginx/html/index.html ./examples/templates/index.html")

        # run
        os.system("sudo python3 ./examples/http3_server.py -c ../certs/prett3.com.pem -k ../certs/prett3.com.key --port 443")


def install_quinn_h3(version):
    if version == '0.0.9':
        os.system("sudo rm -r ./quinn")

        # install dependencies: rust and cmake
        os.system("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sudo sh -s -- -y") 
        os.system("sudo apt install -y cmake")

        # clone H3 (Quinn)
        os.system("git clone https://github.com/hyperium/h3.git")
        os.chdir("h3")
        os.system("git checkout tags/h3-quinn-v0.0.9")

        os.system("sudo /root/.cargo/bin/cargo run --example server -- -d /usr/local/nginx/html/ -l 0.0.0.0:443 -c ../certs/prett3.com.cert.der -k ../certs/prett3.com.key.der")

def install_ngtcp2(version):
    if version == "1.12.0":
        os.system("sudo rm -r ./ngtcp2 ./boringssl ./nghttp3")

        # install dependencies
        os.system("sudo apt install cmake build-essential libssl-dev libbrotli-dev libev-dev pkg-config autoconf automake autotools-dev libtool -y")
        
        # set up boringssl
        os.system("git clone https://boringssl.googlesource.com/boringssl")
        os.chdir("boringssl")
        os.system("git checkout 9295969e1dad2c31d0d99481734c1c68dcbc6403")
        os.system("cmake -B build -DCMAKE_POSITION_INDEPENDENT_CODE=ON")
        os.system("make -j$(nproc) -C build")
        os.chdir("..")

        # set up nghttp3
        os.system("git clone --recursive https://github.com/ngtcp2/nghttp3")
        os.chdir("nghttp3")
        os.system("git checkout tags/v1.9.0")
        os.system("autoreconf -i")
        os.system("./configure --prefix=$PWD/build --enable-lib-only")
        os.system("make -j$(nproc) check")
        os.system("make install")
        os.chdir("..")

        # set up ngtcp2
        os.system("git clone --recursive  https://github.com/ngtcp2/ngtcp2")
        os.chdir("ngtcp2")
        os.system("git checkout tags/v1.12.0")
        os.system("autoreconf -i")
        os.system("./configure PKG_CONFIG_PATH=$PWD/../nghttp3/build/lib/pkgconfig BORINGSSL_LIBS=\"-L$PWD/../boringssl/build -lssl -lcrypto\" BORINGSSL_CFLAGS=\"-I$PWD/../boringssl/include\" --with-boringssl")
        os.system("make -j$(nproc) check")
        
        # run
        os.system("sudo ./examples/bsslserver 0.0.0.0 443 ../certs/prett3.com.key ../certs/prett3.com.crt -d /usr/local/nginx/html/ -q")


def install_xquic(version):
    if version == "1.8.3":
        os.system("sudo rm -r ./xquic")

        os.system("sudo apt install -y build-essential libevent-dev cmake")

        os.system("git clone https://github.com/alibaba/xquic.git")
        os.chdir("xquic")
        os.system("git checkout tags/v1.8.3")

        os.system("git clone https://github.com/google/boringssl.git ./third_party/boringssl")
        os.chdir("./third_party/boringssl")
        os.system("mkdir -p build")
        os.chdir("build")

        os.system("sudo cmake -DBUILD_SHARED_LIBS=0 -DCMAKE_C_FLAGS=\"-fPIC\" -DCMAKE_CXX_FLAGS=\"-fPIC\" ..")
        os.system("make -j2 ssl crypto")
        os.chdir("../../..")


        os.system("git submodule update --init --recursive")
        os.system("mkdir -p build")
        os.chdir("build")

        # os.system("cmake -DGCOV=on -DCMAKE_BUILD_TYPE=Debug -DXQC_ENABLE_TESTING=1 -DXQC_SUPPORT_SENDMMSG_BUILD=1 -DXQC_ENABLE_EVENT_LOG=1 -DXQC_ENABLE_BBR2=1 -DXQC_ENABLE_RENO=1 -DSSL_TYPE=\"boringssl\" -DSSL_PATH=\"../third_party/boringssl\" ..")
        
        os.system("cmake -DGCOV=on " \
    "-DCMAKE_BUILD_TYPE=Release " \
    "-DXQC_ENABLE_TESTING=0 " \
    "-DXQC_SUPPORT_SENDMMSG_BUILD=1 " \
    "-DXQC_ENABLE_EVENT_LOG=0 " \
    "-DXQC_ENABLE_BBR2=1 " \
    "-DXQC_ENABLE_RENO=1 " \
    "-DSSL_TYPE=\"boringssl\" " \
    "-DSSL_PATH=\"../third_party/boringssl\" ..")
        
        os.system("make -j2")
        os.chdir("../scripts")
        
        os.system("sed -i 's/make -j/make -j2/g' xquic_test.sh")
        os.system("sudo bash xquic_test.sh")
        os.chdir("..")

        os.system("cp /usr/local/nginx/html/index.html ./")
        os.system("mv ./server.crt ./server.crt.bak")
        os.system("mv ./server.key ./server.key.bak")
        os.system("cp ../certs/prett3.com.crt ./server.crt")
        os.system("cp ../certs/prett3.com.key ./server.key")

        os.system("sudo ./build/demo/demo_server -p 443")
            
def install_mvfst_proxygen(version):
    # Compiling proxygen, especially folly, requires a lot of computing resources. 
    # Compiling on a machine with a single CPU will fail. Builds successfully on a machine with 4 CPU.
    if version == "2025.04.14.00":
        #os.system("sudo rm -r ./fast_float ./proxygen")
        
        # install fast float system wide
        os.system("git clone https://github.com/fastfloat/fast_float.git")
        os.chdir("fast_float")
        os.system("cmake -B build -DFASTFLOAT_TEST=OFF")
        os.system("sudo cmake --build build --target install")
        
        # install proxygen
        os.chdir("..")
        os.system("git clone https://github.com/facebook/proxygen.git")
        os.chdir("proxygen")
        os.system("git checkout tags/v2025.04.14.00")
        os.chdir("proxygen")
        os.system("bash ./build.sh")
        #os.system("bash ./install.sh") # we don't need to install system-wide
        
        # run proxygen
        os.system("sudo ./_build/bin/hq " \
        "--mode=server --port=443 -host 0.0.0.0 -static_root=/usr/local/nginx/html " \
        "-cert=../../certs/prett3.com.pem -key=../../certs/prett3.com.key")
        

def install_picoquic(version):
    if version=="b19dcf1": # 2025/04/26
        os.system("sudo apt update && sudo apt install -y build-essential cmake libssl-dev libbrotli-dev pkg-config")
        os.system("sudo rm -rf ./picoquic")
        os.system("git clone https://github.com/private-octopus/picoquic.git")
        os.chdir("picoquic")
        os.system("git checkout b19dcf13216c14a1ad7a590fc0c93efade421d25")
        os.system("cmake -DPICOQUIC_FETCH_PTLS=Y .")
        os.system("make")
        os.system("./picoquic_ct") # run tests
        os.system("sudo ./picoquicdemo -p 443 -w /usr/local/nginx/html/  -c ../certs/prett3.com.pem -k ../certs/prett3.com.key -x 10000000")

        
if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='HTTP/3 web servers installation', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("server", help="supported servers \n\t"
    "- nginx\n"
    "- caddy\n"
    "- h2o\n"
    "- ols (lsquic + openlitespeed)\n"
    "- quiche\n"
    "- quic-go\n"
    "- msquic-kestrel\n"
    "- neqo\n"
    "- aioquic\n"
    "- quinn-h3\n"
    "- ngtcp2-nghttp3\n"
    "- xquic\n"
    "- mvfst-proxygen\n"
    "- picoquic\n"
    )

    parser.add_argument("version", help="corresponding version(s) \n\t"
    "- 1.23.4, 1.25.5, 1.27.0 or 1.28.0 \t(for nginx) \n"
    "- 2.4.6, 2.7.6, 2.8.4, 2.10.0\t(for caddy) \n"
    "- a429117, 222b36d, 16b13ee or f1918a5\t(for h2o) \n"
    "- 1.7.15, 1.8.1, 1.8.3.1\t(for ols)\n"
    "- 0.23.5 \t(for quiche)\n"
    "- 0.50.1 \t (for quic-go)\n"
    "- 2.4.8 \t (for msquic-kestrel)\n"
    "- 0.13.1, 0.14.1 \t (for neqo)\n"
    "- 1.2.0 \t (for aioquic)\n"
    "- 0.0.9 \t (for quinn-h3)\n"
    "- 1.12.0 \t (for ngtcp2-nghttp3)\n"
    "- 1.8.3 \t (for xquic)\n"
    "- 2025.04.14.00 \t (for mvfst-proxygen)\n"
    "- b19dcf1 \t (for picoquic)\n"
    )

    args = parser.parse_args()
    server = args.server
    version = args.version
    
    # kill the running webserver processes
    print("[+] Stopping the process running on UDP port 443 ...")
    os.system("sudo sh -c 'kill -9 $(lsof -i UDP:443 -t)' 2>/dev/null")
    os.system("sudo /usr/local/lsws/bin/lswsctrl stop; sudo service lsws stop")
    print("[+] All server killed.")

    if server == 'caddy':
        install_caddy(version)
    elif server == 'nginx':
        install_nginx(version)
    elif server == 'ols':
        install_openlitespeed(version)
    elif server == 'h2o':
        install_h2o(version)
    elif server == "quiche":
        install_quiche(version)
    elif server == "quic-go":
        install_quic_go(version)
    elif server == "msquic-kestrel":
        install_msquic_kestrel(version)
    elif server == "neqo":
        install_neqo(version)
    elif server == "aioquic":
        install_aioquic(version)
    elif server == "quinn-h3":
        install_quinn_h3(version)
    elif server == "ngtcp2-nghttp3":
        install_ngtcp2(version)
    elif server == "xquic":
        install_xquic(version)
    elif server == "mvfst-proxygen":
        install_mvfst_proxygen(version)
    elif server == "picoquic":
        install_picoquic(version)
        

