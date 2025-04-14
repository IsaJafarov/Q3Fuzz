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

def install_nginx(version):
    if version=='1.23.4':
        os.system("sudo apt update && sudo apt install build-essential")
        os.system("sudo rm -r ./nginx-1.23.4; mkdir nginx-1.23.4")
        os.chdir("nginx-1.23.4")
        os.system("cp ../nginx-files/v1.23.4/nginx-quic.tar.gz ./")
        os.system("tar -zxf nginx-quic.tar.gz")
        os.chdir("nginx-quic")
        
        os.system("mkdir ../installation-root")
        
        os.system("./auto/configure --with-debug --with-http_v3_module         \
					   --prefix=../installation-root \
                       --with-cc-opt=\"-I../boringssl/include\"     \
                       --with-ld-opt=\"-L../boringssl/build/ssl    \
                                      -L../boringssl/build/crypto\"")        
        os.system("sudo make")
        os.system("sudo make install")
        os.system("sudo cp ../../nginx-files/v1.23.4/nginx.conf ../installation-root/conf/nginx.conf")

        os.system("sudo ../installation-root/sbin/nginx")
        

    elif version=='1.25.5':
        os.system("sudo apt update && sudo apt install gcc libpcre3-dev libssl-dev zlib1g-dev")
        os.system("sudo rm -r ./nginx-1.25.5; mkdir nginx-1.25.5")
        os.chdir("nginx-1.25.5")
        os.system("cp ../nginx-files/v1.25.5/nginx-1.25.5.tar.gz ./")
        os.system("tar -zxf nginx-1.25.5.tar.gz")
        os.chdir("nginx-1.25.5")
        os.system('./configure \
	--prefix=../installation-root \
	--with-debug \
	--with-http_v3_module \
	--with-cc-opt="-I../boringssl/include" \
	--with-ld-opt="-L../boringssl/build/ssl -L../boringssl/build/crypto"')
        os.system("sudo make")
        os.system("sudo make install")
        os.system("sudo cp ../../nginx-files/v1.25.5/nginx.conf ../installation-root/conf/nginx.conf")
        os.system("sudo ../installation-root/sbin/nginx")

    elif version=='1.27.0':
        os.system("sudo apt update && sudo apt install gcc libpcre3-dev libssl-dev zlib1g-dev")
        os.system("sudo rm -r ./nginx-1.27.0; mkdir nginx-1.27.0")
        os.chdir("nginx-1.27.0")
        os.system("cp ../nginx-files/v1.27.0/nginx-1.27.0.tar.gz ./")
        os.system("tar -zxf nginx-1.27.0.tar.gz")
        os.chdir("nginx-1.27.0")
        os.system('./configure \
	--prefix=../installation-root \
	--with-debug \
	--with-http_v3_module \
	--with-cc-opt="-I../boringssl/include" \
	--with-ld-opt="-L../boringssl/build/ssl -L../boringssl/build/crypto"')
        os.system("sudo make")
        os.system("sudo make install")
        os.system("sudo cp ../../nginx-files/v1.27.0/nginx.conf ../installation-root/conf/nginx.conf")
        os.system("sudo ../installation-root/sbin/nginx")

def install_openlitespeed(version):
    if version=='1.7.15':
        os.system("sudo rm -r ./ols-1.7.15 /usr/local/lsws/; mkdir ./ols-1.7.15")
        os.chdir("ols-1.7.15")
        os.system("cp ../ols-files/v1.7.15/openlitespeed-1.7.15.tgz ./")
        os.system("tar -zxf openlitespeed-1.7.15.tgz")
        os.chdir("openlitespeed")
        os.system("sudo bash install.sh")

        os.system("sudo cp ../../ols-files/v1.7.15/httpd_config.conf /usr/local/lsws/conf/httpd_config.conf")
        
        # Configuration with relative path to the SSL certs didn't work. Put absolute path.
        os.system("sudo sed -i -e s+ssl_cert_path+{}/certs/prett3.com.crt+g /usr/local/lsws/conf/httpd_config.conf".format(current_folder))
        os.system("sudo sed -i -e s+ssl_key_path+{}/certs/prett3.com.key+g /usr/local/lsws/conf/httpd_config.conf".format(current_folder))
        
        os.system("sudo sed -i -e s+'$VH_ROOT/html/'+/usr/local/nginx/html/+g /usr/local/lsws/conf/vhosts/Example/vhconf.conf")

        os.system("sudo /usr/local/lsws/bin/lswsctrl start")

    if version=='1.8.1':
        os.system("sudo rm -r ./ols-1.8.1 /usr/local/lsws/; mkdir ./ols-1.8.1")
        os.chdir("ols-1.8.1")
        os.system("cp ../ols-files/v1.8.1/openlitespeed-1.8.1.tgz ./")
        os.system("tar -zxf openlitespeed-1.8.1.tgz")
        os.chdir("openlitespeed")
        os.system("sudo bash install.sh")

        os.system("sudo cp ../../ols-files/v1.8.1/httpd_config.conf /usr/local/lsws/conf/httpd_config.conf")
        
        # Configuration with relative path to the SSL certs didn't work. Put absolute path.
        os.system("sudo sed -i -e s+ssl_cert_path+{}/certs/prett3.com.crt+g /usr/local/lsws/conf/httpd_config.conf".format(current_folder))
        os.system("sudo sed -i -e s+ssl_key_path+{}/certs/prett3.com.key+g /usr/local/lsws/conf/httpd_config.conf".format(current_folder))
        
        os.system("sudo sed -i -e s+'$VH_ROOT/html/'+/usr/local/nginx/html/+g /usr/local/lsws/conf/vhosts/Example/vhconf.conf")

        os.system("sudo /usr/local/lsws/bin/lswsctrl start")

def install_h2o(version):
    os.system("sudo apt install -y unzip cmake build-essential libssl-dev zlib1g-dev")
    if version=='a429117':
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
    if version=='222b36d':
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
    if version=='16b13ee':
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
    
def install_quiche(version):
    if version == '0.23.5':
        os.system("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sudo sh") # install rustub https://rustup.rs/
        os.system("sudo apt install -y cmake")
        os.system("sudo rm -r ./quiche-0.23.5; mkdir ./quiche-0.23.5")
        os.chdir("quiche-0.23.5")
        os.system("cp ../quiche-files/v0.23.5/quiche_0.23.5.tar.gz ./")
        os.system("tar -zxf quiche_0.23.5.tar.gz")
        os.system("cp ../quiche-files/v0.23.5/boringssl.tar.gz ./quiche-0.23.5/quiche/deps/boringssl")
        os.system("tar -zxf ./quiche-0.23.5/quiche/deps/boringssl/boringssl.tar.gz -C ./quiche-0.23.5/quiche/deps/boringssl/")
        os.system("mv ./quiche-0.23.5/quiche/deps/boringssl/boringssl-0.20250311.0/* ./quiche-0.23.5/quiche/deps/boringssl/")
        os.chdir("quiche-0.23.5")
        #os.system("sudo env RUSTFLAGS=\"-C link-args=-lstdc++\" $HOME/.cargo/bin/cargo build --examples")
        os.system("sudo env RUSTFLAGS=\"-C link-args=-lstdc++\" $HOME/.cargo/bin/cargo run --bin quiche-server -- --listen 0.0.0.0:443 --cert ../../certs/prett3.com.crt --key ../../certs/prett3.com.key --root /usr/local/nginx/html/ --name prett3.com")

def install_quic_go(version):
    if version == '0.50.1':
        os.system("sudo rm -r ./quic-go-0.50.1; mkdir ./quic-go-0.50.1")
        os.chdir("quic-go-0.50.1")
        os.system("wget https://go.dev/dl/go1.24.2.linux-amd64.tar.gz")
        os.system("sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.24.2.linux-amd64.tar.gz") # https://go.dev/doc/install
        os.system("cp ../quic-go-files/v0.50.1/v0.50.1.tar.gz ./")
        os.system("tar -zxf v0.50.1.tar.gz")
        os.chdir("quic-go-0.50.1")
        os.system("sudo /usr/local/go/bin/go run example/main.go -bind 0.0.0.0:443 -www /usr/local/nginx/html/ -cert ../../certs/prett3.com.crt -key ../../certs/prett3.com.key")

def install_msquic_kestrel(version):
    if version == '2.4.8':
        os.system("sudo rm -r ./msquic_kestrel; mkdir ./msquic_kestrel")
        os.chdir("msquic_kestrel")
        # install msquic library
        os.system("wget -q https://packages.microsoft.com/keys/microsoft.asc -O- | sudo apt-key add -")
        os.system("sudo add-apt-repository \"deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-ubuntu-$(lsb_release -cs)-prod $(lsb_release -cs) main\"")
        os.system("sudo apt update")
        # install the latest (2.4.8) libmsquic. Previous versions causes problems https://github.com/dotnet/runtime/issues/105788
        os.system("sudo apt install -y libmsquic=2.4.8")

        # install .NET SDK
        os.system("sudo add-apt-repository ppa:dotnet/backports")
        os.system("sudo apt update")
        os.system("sudo apt install -y dotnet-sdk-9.0=9.0.203-1")

        # create .NET project
        os.system("dotnet new web -n Http3Server")
        os.chdir("Http3Server")
        os.system("cp ../msquic-kestrel-files/Program.cs ./")
        os.system("sudo dotnet run")
        


if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='HTTP/3 web servers installation', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("server", help="supported servers \n\t"
    "- nginx\n"
    "- caddy\n"
    "- h2o\n"
    "- ols (openlitespeed)\n"
    "- quiche\n"
    "- quic-go\n"
    "- msquic-kestrel"
    )

    parser.add_argument("version", help="corresponding version(s) \n\t"
    "- 1.23.4, 1.25.5 or 1.27.0 \t(for nginx) \n"
    "- 2.4.6, 2.7.6, 2.8.4\t(for caddy) \n"
    "- a429117, 222b36d or 16b13ee\t(for h2o) \n"
    "- 1.7.15 or 1.8.1\t(for ols)\n"
    "- 0.23.5 \t(for quiche)\n"
    "- 0.50.1 \t (for quic-go)\n"
    "- 2.4.8 \t (for msquic-kestrel)"
    )
    args = parser.parse_args()
    server = args.server
    version = args.version
    
    # kill the running webserver processes
    #os.system("sudo pkill -9 nginx")
    #os.system("sudo pkill -9 caddy")
    #os.system("sudo pkill -9 h2o")
    #os.system("sudo /usr/local/lsws/bin/lswsctrl stop; sudo service lsws stop")
    # TODO add ll servers
    os.system("sudo pkill -9 dotnet")    

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


