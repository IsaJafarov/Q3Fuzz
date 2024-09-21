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
    os.system("sudo ./caddy run")

def run_nginx(version):
    print("[+] Running nginx %s..." % version)
    if version=='1.23.4':
        os.chdir("./nginx-1.23.4/nginx-1.23.4")
    elif version=='1.25.5':
        os.chdir("./nginx-1.25.5/nginx-1.25.5")
    elif version=='1.27.0':
        os.chdir("./nginx-1.27.0/nginx-1.27.0")
    os.system("sudo ../installation-root/sbin/nginx")

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

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='HTTP/3 web servers runner')
    parser.add_argument("server", help="Server name (nginx, caddy, h2o, ols)")
    parser.add_argument("version", help="corresponding version(s) \n\t- 1.23.4, 1.25.5 or 1.27.0 \t(for nginx) \n\t- 2.4.6, 2.7.6, 2.8.4\t(for caddy)\n\t- a429117, 222b36d or 16b13ee\t(for h2o)\n\t- 1.7.15 or 1.8.1\t(for ols)")
    args = parser.parse_args()
    server = args.server
    version = args.version
    
    # kill the running webserver processes
    print("[+] Stopping nginx, litespeed ...")
    os.system("sudo pkill -9 nginx")
    os.system("sudo pkill -9 caddy")
    os.system("sudo pkill -9 h2o")
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

    print("[+] Done.")
