<?php

if ($argc < 2 ) {
    exit( "DNS axfr scanner, find name servers who doesn't block dig axfr thus revealing all of their precious secrets.\n
		 Usage: php axfr.php domain.tld \n
		 OR php axfr.php --file file.txt\n
		 where file.txt has a list of domains, one domain per line.\n" );
}

if ($argv[1]=="--file" && false===empty($argv[2])) {
	if (false === file_exists($argv[2])) die ("cannot find file ".$argv[2]."\n");
	$domains = file($argv[2]);
} else $domains=[$argv[1]];

function get_ns($domain) {
	return @dns_get_record($domain, DNS_NS);
}

function check_axfr($domain, $ns) {
	$cmd = "timeout 5 dig axfr @".$ns." ".$domain;
	$output = shell_exec($cmd);
	if (empty($output)) return 0;
	$lines = explode("\n", $output);
	$lineCounter=0;
	foreach ($lines as $line) {
		if (empty(trim($line)) || $line[0]==";") continue;
		$lineCounter++;
	}
	return $lineCounter > 1;
}

foreach ($domains as $domain) {
	$domain=trim($domain);
	echo "\nCHECKING: ".$domain;
	$nss=get_ns($domain);
	if (false == is_array($nss)) {echo " ... ERROR: CANNOT FIND NS RECORDS"; continue;}
	foreach ($nss as $ns) 
		if (check_axfr($domain, $ns['target'])) echo " ... FOUND: ".$ns['target']." ".$domain;
}
echo "\nDONE\n";
