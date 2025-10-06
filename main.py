from phoca2.phoca import phoca_url_detect 
from ClickGrab.clickgrab import clickgrab_url_detect 
from clicjack.clickjack import clickjack_url_detect
from termcolor import colored
# use async concurrent function calls 
print(colored("Checking MITM Vulnerability using Phoca... \n", "cyan"))
print(phoca_url_detect("https://login.ghcat.tech")) 
print(colored("\nChecking ClickGrab Vulnerability... \n", "cyan"))
print(clickgrab_url_detect("https://www.bratusferramentas.grupomoltz.com.br/"))
print(colored("\nChecking ClickJacking Vulnerability... \n", "cyan"))
print(clickjack_url_detect("https://sanjay7178.github.io/Kubernetes-Conf/test/attacker-site.html"))
