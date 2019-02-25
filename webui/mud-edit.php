<?php

/* We've just received a JSON array.  Not all elements are editable.
 * In fact, we'll want to display entries one at a time.
 */

session_start();

require_once 'vendor/autoload.php';
require_once 'funcs.php';

$config="/usr/local/etc/mud_manager_conf.json";
read_config($config,$basic,$configmans,$configvlans,$configdefaults);

function editDB($coll,$qkey,$qvalue,$ukey,$uvalue,$upsert) {
    
    try {
        $update=$coll->findOneAndUpdate(
            [ $qkey => $qvalue ], // query
            [ '$set' => [ $ukey => $uvalue ]], /* edit */
            [ 'upsert' => $upsert,/* options */
            'returnDocument' =>
            MongoDB\Operation\FindOneAndUpdate::RETURN_DOCUMENT_AFTER]); 
    }
    catch(MongoResultException $e) {
        print "<br>editDB: " . $qkey . " " . $qvalue . " " . $ukey .
            " " . $uvalue . "<br><pre>";
        
        echo $e->getCode(), " : ", $e->getMessage(), "\n";
        var_dump($e->getDocument());
        print "</pre>";
        exit;
    }
}

function queryDB($coll,$query,$element) 
{
    try {
        $update=$coll->findOne($query); // query
    }
    catch(MongoResultException $e) {
        print "<br>queryDB: " . $query . " " . $element . "<br><pre>";
        echo $e->getCode(), " : ", $e->getMessage(), "\n";
        var_dump($e->getDocument());
        print "</pre>";
        exit;
    }
    
    if (isset($update)) {
        return($update[$element]);
    } else {
        return(null);
    }
}


function deleteOne($coll,$query) 
{
    try {
        $update=$coll->deleteOne($query); // query
    }
    catch(MongoResultException $e) {
        print "deleteOne: " . $query . "<pre>";

        echo $e->getCode(), " : ", $e->getMessage(), "\n";
        var_dump($e->getDocument());
        print "</pre>";
        exit;
    }
}

function bootserver($list) 
{
    $json= '{  "Update_URLs" : [ ';
    
    for ($i=0; $i< sizeof($list); $i++) {
        $json = $json . ' "' . $list[$i] . '" ';
        if ($i < (sizeof($list) - 1)) {
            $json = $json . ', ';
        }
    }
    $json = $json . ' ] }';

    /* ok, do the curl to the server. */
    $curl= curl_init();
    curl_setopt($curl, CURLOPT_POST, 1);
    curl_setopt($curl,CURLOPT_POSTFIELDS, $json);
    curl_setopt($curl, CURLOPT_URL, "http://localhost:8000/cfg_change");
    curl_setopt($curl,CURLOPT_RETURNTRANSFER, 1);
    $result=curl_exec($curl);
    curl_close($curl);

}

    



/* first read in JSON array. */

$json=$_POST["json"];

$top=json_decode($json,$assoc=true);

$k=json_last_error();
if ( $k != JSON_ERROR_NONE ) {
    print "JSON error: " . json_last_error_msg();
	exit;
}

$indices=json_decode($_POST["indices"]);

$k=json_last_error();

if ( $k != JSON_ERROR_NONE ) {
    print "JSON error: " . json_last_error_msg();
	exit;
}

/* so here's the situation. in the last array entry we have the index
 * needed to find the index into the appropriate database collection.
 * yeah, that's index->index->entry.  Yuck, but that's the web for you.
 */

$url_idx=0;


for ( $i = 0; $i < sizeof($top); $i++) {
    $e=$top[$i];

    // create an associative array of an array of elements for our convenience.
    $row= [ 'devtype' => $e[0], 'controller' => $e[1],
    'vlan' => $e[2], 'netmask' => $e[3], 'policies' => $e[4],
    'source' => $e[5], 'desc' => $e[6] , 'index' => $indices[intval($e[7])]];
    $table[$i]=$row;

}

init_database($client,$mudfile_collection,$vlan_collection,
             $policies_collection);

for ( $i=0;$i< sizeof($table); $i++) {
    $row=$table[$i];
    $rules=$row['source'];
    
    switch($row['source']) {
    case "MUD state": /* here the index points to a URL.  
                       *  Update MUD file and policies DB. */
        /* check value of controller.  it should be an IP address.
         * If not, don't update it.
         */
        if ( filter_var($row['controller'],FILTER_VALIDATE_IP) )  {
            editDB($mudfile_collection,'URI',$row['index'],
               'Controller',$row['controller'],false);
        }
        
        /* now do the VLAN and netmask in the policies and VLAN databases.
         *Treat as a number. */
        
        $num=(int) $row['vlan'];
        $url=$row['index'];
        $url_list[$url_idx++]=$url;
        $url_bits=parse_url($url);
        $host=$url_bits['host'];

        if ( $num > 0 ) {       /* only update vlan if we have one */

            /* if row exists, update, if it doesn't exist, create it. */
            /* check first against the mud-url. */

            $oldmask=queryDB($vlan_collection,[ 'VLAN_ID' => $num ],
                    'v4addrmask');
            $oldvlan=queryDB($vlan_collection,
                              [ "Owner" => [ '$in' => [ $url, $host ]] ],
                              'VLAN_ID');
            
            if ( ($oldvlan == $num) ) { // only update the v4addrmask.
                $update=editDB($vlan_collection,"VLAN_ID", $num,
                               'v4addrmask',$row['netmask'], false);
            } else {
                /* We change VLANs-
                 * We *only* do this per MUD-URL, not per manufacturer.  This is
                 * a bit of a limitation, in that one might want a bulk change.
                 * For now, too bad.
                 */

                /* remove entry from any existing VLAN DB Owner arrays. */
                


                try {
                    $update=$vlan_collection->updateMany([],
                    [ '$pull' => [ "Owner" => $url ] ]);
                }
                catch(MongoResultException $e) {
                    echo $e->getCode(), " : ", $e->getMessage(), "\n";
                    var_dump($e->getDocument());
                }
                
                // ok, that cleaned out the cruft.  Now we need to do the
                // new push.  don't do this for the default.  That is-
                // upsert = false.

                if ( $num != $basic['Default_VLAN'] ){
                    
                    $update=$vlan_collection->findOneAndUpdate(
                        [ "VLAN_ID" => $num ],
                        [ '$push' => [ "Owner" => $url ] ], [ 'upsert' => true ]);
                    /* now update v4addrmask. */
                    editDB($vlan_collection, "VLAN_ID", $num,
                    'v4addrmask',$row['netmask'],false);
                    /* whack policies collection with new VLAN_ID */
                }
                print "<br>whacking " . $url . "to be " . $num . "<br>";
                
                try {
                    $update=$policies_collection->updateMany(
                        ['URI' => $url],
                        ['$set' => ["VLAN" => $num]]);
                }
                catch(MongoResultException $e) {
                    echo $e->getCode(), " : ", $e->getMessage(), "\n";
                    var_dump($e->getDocument());
                }
            }
        }
    
        break;
    case "VLAN DB": // VLANs join the party here.
        $num=(int) $row['vlan'];
        $idx=(int) $row['index'];
        if ( $num > 0 ) {
            editDB($vlan_collection, 'VLAN_ID', $idx,
                'VLAN_ID',$num,false);
            editDB($vlan_collection, 'VLAN_ID', $idx,
                'v4addrmask',$row['netmask'],false);
        }
    }
}

bootserver($url_list);

$_SESSION['update']='true';

header('Location: mud-home.php');


