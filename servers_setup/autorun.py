import os, argparse

current_folder = os.path.dirname(os.path.abspath(__file__))
os.chdir(current_folder)

def run_caddy(version):
    print("[+] Running caddy %s..." % version)
    if version=='2.7.6':
        os.chdir("caddy-2.7.6")
        os.system("pwd")
        os.system("sudo ./caddy run")

def run_nginx(version):
    print("[+] Running nginx %s..." % version)
    if version=='1.25.5':
        os.chdir("nginx-1.25.5")
        os.chdir("nginx-1.25.5")
        os.system("sudo ../installation-root/sbin/nginx")

def run_openlitespeed(version):
    print("[+] Running openlitespeed %s..." % version)
    if version=='1.8.1':
        os.chdir("ols-1.8.1")
        os.chdir("openlitespeed")
        os.system("sudo /usr/local/lsws/bin/lswsctrl start")

def run_h2o(version):
    print("[+] Running h2o %s..." % version)
    if version=='222b36d':
        os.chdir("h2o-222b36d")
        os.chdir("h2o-222b36d7bd3a98616eae82993552098747268d5e")
        os.chdir("build")
        os.system("sudo ./h2o -c ../examples/h2o/h2o.conf")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='HTTP/3 web servers runner')
    parser.add_argument("server", help="Server name (nginx, caddy, h2o, ols)")
    parser.add_argument("version", help="Version (1.25.5 for nginx, 2.7.6 for caddy, 222b36d for h2o, 1.8.1 for openlitespeed)")
    args = parser.parse_args()
    server = args.server
    version = args.version
    
    # kill the running webserver processes
    print("[+] Stopping nginx, litespeed ...")
    os.system("sudo pkill -9 nginx")
    os.system("sudo pkill -9 litespeed")
    print("[+] All server killed.")
    
    if server == 'caddy':
        run_caddy(version)
    elif server == 'nginx':
        run_nginx(version)
    elif server == 'ols':
        run_openlitespeed(version)
    elif server == 'h2o':
        run_h2o(version)

    print("[+] Done.")