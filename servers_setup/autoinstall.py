import os, argparse

current_folder = os.path.dirname(os.path.abspath(__file__))
os.chdir(current_folder)

def install_caddy(version):
    if version=='2.7.6':
        os.system("rm -r ./caddy-2.7.6; mkdir caddy-2.7.6")
        os.chdir("caddy-2.7.6")
        os.system("pwd")
        os.system("cp ../caddy-files/v2.7.6/caddy ./")
        os.system("cp ../caddy-files/v2.7.6/Caddyfile ./")
        os.system("sudo ./caddy run")

def install_nginx(version):
    if version=='1.25.5':
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

def install_openlitespeed(version):

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
        

if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='HTTP/3 web servers installation')
    parser.add_argument("server", help="Server name (nginx, caddy, h2o, ols)")
    parser.add_argument("version", help="Version (1.25.5 for nginx, 2.7.6 for caddy, 222b36d for h2o, 1.8.1 for openlitespeed)")
    args = parser.parse_args()
    server = args.server
    version = args.version
    
    # kill the running webserver processes
    os.system("sudo pkill -9 nginx")
    os.system("sudo pkill -9 litespeed")
    

    if server == 'caddy':
        install_caddy(version)
    elif server == 'nginx':
        install_nginx(version)
    elif server == 'ols':
        install_openlitespeed(version)
    elif server == 'h2o':
        install_h2o(version)