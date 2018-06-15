<?php

/**
 * Simple WHOIS Lookup
 * By NimaH79
 * NimaH79.ir
 */

function isDomainAvailable($domain) {
    $domain_parts = explode('.', $domain);
    $tld = strtolower(array_pop($domain_parts));
    $xml = simplexml_load_file(__DIR__.'/whois-server-list.xml');
    $server = xml2array($xml->xpath('/domainList/domain[@name="'.$tld.'"]'));
    if(!empty($server)) {
        $whois_server = $server[0]['whoisServer']['@attributes']['host'];
        $available_pattern = $server[0]['whoisServer']['availablePattern'];
        $fp = @fsockopen($whois_server, 43, $errno, $errstr, 10) or die('Socket Error '.$errno.' - '.$errstr);
        fputs($fp, $domain."\r\n");
        $result = '';
        while(!feof($fp)){
            $result .= fgets($fp);
        }
        fclose($fp);
        if(preg_match('/'.$available_pattern.'/i', $result)) {
            return $domain.' is available!';
        }
        return $domain.' is not available.';
    }
    else {
        return 'TLD not found.';
    }
}

function xml2array($xmlObject, $out = array()) {
    foreach ( (array) $xmlObject as $index => $node )
        $out[$index] = ( is_object ( $node ) ) ? xml2array ( $node ) : $node;

    return $out;
}

// Example
echo isDomainAvailable('nimah79.ir');