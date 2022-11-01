import pandas as pd
import plotext
import re
import argparse
from tabulate import tabulate


pd.set_option('display.max_colwidth', None)
parser = argparse.ArgumentParser()
parser.add_argument('csv', help="CSV to load")
parser.add_argument('--risk', action='store_true', help='Show the vulnerabilities by Risk')
parser.add_argument('--vulns', action='store_true', help='Show the vulnerabilities')
parser.add_argument('--v', action='store', help='Show the vulnerabilities by Risk',type=str)
parser.add_argument('--host', action='store_true', help='Show the vulnerabilities by Host')
parser.add_argument('--all', action='store_true', help='Show all available information')

args = parser.parse_args()
print(args.csv)

def hosts(df):
	df=df
	hosts = list(df['Host'].value_counts().keys())
	count = df['Host'].value_counts().tolist()
	#plotext.title('vulnerabilities per host')
	plotext.simple_bar(hosts,count,title="Vulnerabilities per host")
	plotext.show()
def vulns(df):
	df=df
	vuln_name = []
	vuln_host = []
	vuln_risk = []
	vuln_count = []
	#print(list(set(df['Name'].tolist())))
	for x in list(set(df['Name'].tolist())):
		all_vulns = df[['Host','Name','Port','Risk']].loc[(df['Name'] == x)]
		#all_vulns.reset_index(drop=True, inplace=True)
		vuln_name.append(x)
		vuln_host.append(', '.join(list(set(all_vulns['Host'].tolist()))))
		vuln_risk.append(', '.join(list(set(all_vulns['Risk'].tolist()))))
		vuln_count.append(all_vulns['Name'].tolist().count(str(x)))
		data = {'Vulnerability': vuln_name, 'Hosts': vuln_host, 'Risk': vuln_risk, 'Count': vuln_count}
	return print(tabulate(data, headers='keys', tablefmt='psql'))


data = pd.read_csv(args.csv,sep=',', encoding='UTF-8')
df = data.loc[(data['Risk'] != 'None')]
if args.all:
	data = {'Criticity': list(df['Risk'].value_counts().keys()),'# vulns': df['Risk'].value_counts().tolist()}
	df2 = pd.DataFrame(data)
	print(tabulate(df2, headers='keys', tablefmt='psql'))
	vulns(df)
	hosts(df)

if args.risk:
	data = {'Criticity': list(df['Risk'].value_counts().keys()),'# vulns': df['Risk'].value_counts().tolist()}
	df2 = pd.DataFrame(data)
	print(tabulate(df2, headers='keys', tablefmt='psql'))
if args.vulns:
	if args.v:
		vulne = df[['Host','Name','Plugin Output']].loc[(df['Name'] == args.v)].replace({'\n':''}, regex=True).reset_index()
		print(vulne[['Host','Plugin Output']])
		#print(tabulate(vulne, headers='keys', tablefmt='psql'))
	else:
		vulns(df)

if args.host:
	hosts(df)

