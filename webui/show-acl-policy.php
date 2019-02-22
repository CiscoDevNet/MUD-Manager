<?php

/* Simple routine to show ACL policies. */

require_once 'vendor/autoload.php';

require_once 'funcs.php';
require_once 'statics.php';


/*$client='';
$mud_collection='';
$vlan_collection='';
$mfgr_collection='';
$policies_collection='';
*/
init_database($client,$mud_collection,$vlan_collection,
              $policies_collection);


/* this script takes as a single argument the name of the policy.
 */

if (! isset($_GET['mudurl'] )) {
    print "Bad form!";
    exit;
}
$url=$_GET['mudurl'];

$policies=$policies_collection->find([ 'URI' => $url ]);

print $begin;
print "<h2>Policies for devices with MUDURL " . $url . ":</h2>";



foreach ( $policies as $policy ) {

    print "<pre>";
    $p_array=iterator_to_array($policy);
    
    foreach ( array_keys($p_array) as $key) {
        switch ( $key ) {
        case "_id":
            break;
        case "DACL":
            $p_array[$key]=str_replace("," , ",\n\t" ,$p_array[$key]);
        default:
            print $key . ": " . $p_array[$key] . "\n";
        }
    }
    print "</pre><hr>";
}
