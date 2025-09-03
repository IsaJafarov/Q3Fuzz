import os, argparse

current_folder = os.path.dirname(os.path.abspath(__file__))
os.chdir(current_folder)

def run_caddy(version):
    print("[+] Running caddy %s..." % version)
    if version=='2.4.6':
        os.chdir("caddy-2.4.6")
    elif version=='2.7.6':
        os.chdir("caddy-2.7.6")
    elif version=='2.8.4':
        os.chdir("caddy-2.8.4")
    elif version=='2.10.0':
        os.chdir("caddy-2.10.0")
    os.system("sudo ./caddy run")

def run_nginx(version):
    print("[+] Running nginx %s..." % version)
    if version=='1.23.4':
        os.chdir("./nginx-quic")
    elif version=='1.25.5':
        os.chdir("./nginx-1.25.5")
    elif version=='1.27.0':
        os.chdir("./nginx-1.27.0")
    elif version=='1.28.0':
        os.chdir("./nginx-1.28.0")
    os.system("sudo ./installation-root/sbin/nginx")

def run_openlitespeed(version):
    print("[+] Running openlitespeed %s..." % version)
    os.system("sudo /usr/local/lsws/bin/lswsctrl start")

def run_h2o(version):
    print("[+] Running h2o %s..." % version)
    if version=='a429117':
        os.chdir("h2o-a429117")
        os.chdir("h2o-a429117babff09542d3517c4fa36c1ef769889c1")
    elif version=='222b36d':
        os.chdir("h2o-222b36d")
        os.chdir("h2o-222b36d7bd3a98616eae82993552098747268d5e")
    elif version=='16b13ee':
        os.chdir("h2o-16b13ee")
        os.chdir("h2o-16b13eee8ad7895b4fe3fcbcabee53bd52782562")
    os.chdir("build")
    os.system("sudo ./h2o -c ../examples/h2o/h2o.conf")

    
def run_quiche(version):
    print("[+] Running quiche %s..." % version)
    if version == '0.23.5':
        os.chdir("quiche")
        os.system("sudo ./target/debug/quiche-server --listen 0.0.0.0:443 --cert ../certs/prett3.com.crt --key ../certs/prett3.com.key --root /usr/local/nginx/html/ --no-retry --name prett3.com")

def run_quic_go(version):
    print("[+] Running quic_go %s..." % version)
    if version == '0.50.1':
        os.chdir("quic-go")
        os.system("sudo /usr/local/go/bin/go run example/main.go -bind 0.0.0.0:443 -www /usr/local/nginx/html/ -cert ../certs/prett3.com.crt -key ../certs/prett3.com.key")

def run_msquic_kestrel(version):
    print("[+] Running msquic + kestrel %s..." % version)
    if version == '2.4.8':    
        os.chdir("msquic_kestrel")
        os.system("sudo dotnet run")
        
def run_neqo(version):
    print("[+] Running neqo %s..." % version)
    if version == '0.13.1':
        os.chdir("neqo")
        os.system("sudo env LD_LIBRARY_PATH=\"$(realpath ./dist/Debug/lib)\" RUST_BACKTRACE=full ./target/release/neqo-server 0.0.0.0:443 -d ./certdb/ -k \"prett3.com - CUNY\"")

def run_aioquic(version):
    print("[+] Running aioquic %s..." % version)
    if version == '1.2.0':
        os.chdir("aioquic")
        os.system("sudo python3 ./examples/http3_server.py -c ../certs/prett3.com.pem -k ../certs/prett3.com.key --port 443 -v")
        
def run_quinn_h3(version):
    print("[+] Running quinn + h3 %s..." % version)
    if version == '0.0.9':
        os.chdir("h3")
        os.system("sudo /root/.cargo/bin/cargo run --example server -- -d /usr/local/nginx/html/ -l 0.0.0.0:443 -c ../certs/prett3.com.cert.der -k ../certs/prett3.com.key.der")

def run_ngtcp2(version):
    print("[+] Running ngtcp2 + nghttp3 %s..." % version)
    if version == "1.12.0":
        os.system("sudo ./ngtcp2/examples/bsslserver 0.0.0.0 443 ./certs/prett3.com.key ./certs/prett3.com.crt -d /usr/local/nginx/html/")

def run_xquic(version):
    if version == "1.8.3":
        os.chdir("xquic")
        os.system("sudo ./build/demo/demo_server -p 443")

def run_mvfst_proxygen(version):
    if version == "2025.04.14.00":
        os.chdir("proxygen/proxygen")
        os.system("sudo ./_build/bin/hq " \
        "--mode=server --port=443 -host 0.0.0.0 -static_root=/usr/local/nginx/html " \
        "-cert=../../certs/prett3.com.pem -key=../../certs/prett3.com.key")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='HTTP/3 web servers runner', formatter_class=argparse.RawTextHelpFormatter)
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
    )

    parser.add_argument("version", help="corresponding version(s) \n\t"
    "- 1.23.4, 1.25.5 or 1.27.0 \t(for nginx) \n"
    "- 2.4.6, 2.7.6, 2.8.4, 2.10.0\t(for caddy) \n"
    "- a429117, 222b36d or 16b13ee\t(for h2o) \n"
    "- 1.7.15 or 1.8.1\t(for ols)\n"
    "- 0.23.5 \t(for quiche)\n"
    "- 0.50.1 \t (for quic-go)\n"
    "- 2.4.8 \t (for msquic-kestrel)\n"
    "- 0.13.1 \t (for neqo)\n"
    "- 1.2.0 \t (for aioquic)\n"
    "- 0.0.9 \t (for quinn-h3)\n"
    "- 1.12.0 \t (for ngtcp2-nghttp3)\n"
    "- 1.8.3 \t (for xquic)\n"
    "- 2025.04.14.00 \t (for mvfst-proxygen)\n"
    )

    args = parser.parse_args()
    server = args.server
    version = args.version
    
    # kill the running webserver processes
    print("[+] Stopping the process running on UDP port 443 ...")
    os.system("sudo kill -9 $(sudo lsof -i UDP:443 -t)")
    os.system("sudo /usr/local/lsws/bin/lswsctrl stop; sudo service lsws stop")
    print("[+] All server killed.")
    
    if server == 'caddy':
        run_caddy(version)
    elif server == 'nginx':
        run_nginx(version)
    elif server == 'ols':
        run_openlitespeed(version)
    elif server == 'h2o':
        run_h2o(version)
    elif server == "quiche":
        run_quiche(version)
    elif server == "quic-go":
        run_quic_go(version)
    elif server == "msquic-kestrel":
        run_msquic_kestrel(version)
    elif server == "neqo":
        run_neqo(version)
    elif server == "aioquic":
        run_aioquic(version)
    elif server == "quinn":
        run_quinn_h3(version)
    elif server == "ngtcp2-nghttp3":
        run_ngtcp2(version)
    elif server == "xquic":
        run_xquic(version)
    elif server == "mvfst-proxygen":
        run_mvfst_proxygen(version)

    print("[+] Done.")
