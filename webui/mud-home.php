<?php

/* Create a simple management interface for the mud_manager tool.
 * (or at least try to make it look simple)
 */

session_start();

require_once 'vendor/autoload.php';
require_once 'statics.php';
require_once 'funcs.php';

$config="/usr/local/etc/mud_manager_conf.json";
$serial=0;
$rownum=0;



read_config($config,$basic,$mans,$vlans,$defaults);

/* We have configuration.  Let's initialize the Mongo Database.
 */

print $begin;
   
init_database($client,$mudfile_collection,$vlan_collection,
              $policies_collection);


/* ok, let's go build a table: It looks like this:
 *
 * Device type| Controller | VLAN | net mask | Policies | Description
 * $devtype | $controller |  $VLAN | $v4mask | $policies | $desc
 */


/* We need to consider two sources.  What is live in the database, and what
 * is in the configuration.  We will mix and match.  A lot.  To merge, we
 * will make use of the authority and the MUD URL.  We will create the table
 * in memory, row by row, and then output it.
 */

/* let's start with what we have in the db. */

$mud_cursor=$mudfile_collection->find();

print $table_front;

foreach ($mud_cursor as $mud_entry) {
    $devtype='';
    $controller='';
    $VLAN='';
    $v4mask='';
    $policies='';
    $desc='';

    /* first cell: Device type */
    $mud_uri=$mud_entry["URI"];
    
    $authority=parse_url($mud_uri,PHP_URL_HOST);

    /* do some heuristics for what to put in this collumn */

    if (isset($mud_entry["Manufacturer-Label"])) {
        $c=$mud_entry["Manufacturer-Label"];
    } else { // whack the MUD-URL into an authority
        $c=$authority;
    }
    // next add the model if it exists.
    if ( isset($mud_entry["Manufacturer-Model"]) ) {
        $c = $c . " " . $mud_entry["Manufacturer-Model"];
    }
    $devtype= makecolumn($c);
    
    /* on to $controller.  This must come either from the database or
     * config.
     */

    /* always try the db first. */

    if (isset($mud_entry['Controller'])) {
        $controller=$mud_entry['Controller'];
    } else {
        for ($i=0;$i< sizeof($mans); $i++) {
            /* mans uses authority.  It's what we have. */
            $e = $mans[$i];
            if ($e["authority"] == $authority) {
                if ( isset($e["my_controller_v4"])) {
                    $controller = $e["my_controller_v4"];
                }
                unset($mans[$i]);
            }
        }
    }
        
    /* wrap $controller in an td input */
    if ( $controller != '') {
        $controller = makecol($controller,"text","ctrlr",$serial++);
    } else {
        if ( isset($mud_entry["Needs-my-controller"])  && 
        ( $mud_entry["Needs-my-controller"]== "yes" )) {
            $controller= '<span style="color:Tomato;">none available</span>';
        } else {
            $controller="";
        }
        
        $controller=makecolumn($controller);
    }
    
    
    // Do VLAN.

    $vlan_array=$vlan_collection->findOne([ "Owner" => 
                                        [ '$in' => [ $mud_uri ] ]]);
    if ( $vlan_array == NULL ) {
        $vlan_array=$vlan_collection->findOne([ "Owner" => 
                                        [ '$in' => [ $authority ] ]]);
    }
            
    if ( $vlan_array != NULL ) {
        $VLAN=$vlan_array["VLAN_ID"];
        $v4mask=$vlan_array["v4addrmask"];
        $v6mask=$vlan_array["v6addrmask"];
    } else {
        // check to see if we have a default.
        if ( isset($basic['Default_VLAN'])) {
            $VLAN=$basic['Default_VLAN'];
            $v4mask=$basic['Default_Localv4'];
            $v6mask=$basic['Default_Localv6'];
        }
    }


    $VLAN=makecol($VLAN,"number","vlan",$serial++);
    $v4mask=makecol($v4mask,"text","v4msk",$serial++);
    
    // on to policies.  There are as many as three sets: 
    //  * the mud file
    //  * inbound
    //  * outbound
    
    // The MUD file will be found in the current mud_entry.  We want
    // a pointer tho, and so we'll just point to the MUD URL.

    $policies='<a href="' . $mud_uri . '">(mud file)</a> ';
    $policies= $policies . '<a href="show-acl-policy.php?mudurl=' . $mud_uri .
        '">(DACLs)</a>';
    $policies= makecolumn($policies);
    if ( isset($mud_entry["Manufacturer-Doc"]) ) {
        $docs=' <a href="' . $mud_entry["Manufacturer-Doc"] . '">(docs)</a>';
    } else {
        $docs='';
    }
    $desc= $mud_entry["Systeminfo"] . " " . $docs;
    if ( strlen($desc) > 22 ) {
        $desc='<span style="font-size: 80%;">' . $desc . '</span>';
    }
    $desc=makecolumn($desc);
    
    /* Great! we have a row! */
    $rowsource[$rownum]=makecolumn('MUD state');
    $indices[$rownum]=$mud_uri;
    makerow($devtype,$controller,$VLAN,$v4mask,
        $policies,$desc,$rowsource[$rownum],$rownum++);
}


// Ok, so what remains are manufacturers that are in the config file
// and VLANs that aren't used.  Let's tackle manufacturers first.

for ($i=0; $i<sizeof($mans); $i++) {
    $man_entry=$mans[$i];
    $authority=$man_entry["authority"];
    $devtype= makecolumn($man_entry["authority"]);
    if ( isset($man_entry['my_controller_v4']) ) {
        $c=$man_entry['my_controller_v4'];
    }  else {
        $c='';
    }
    $controller=makecol($c,"text",'manctl',$serial++);
    
    // check for a VLAN in the VLANs table.
    $VLAN='';
    $v4mask='';
    $v6mask='';
    $ventry=$vlan_collection->findOne([ "Owner" => 
              [ '$in' => [ $authority ] ]]);
    if ( $ventry != NULL ) {
        $VLAN=$ventry["VLAN_ID"];
        $v4mask=$ventry["v4addrmask"];
        $v6mask=$ventry["v6addrmask"];
        
    } else {
        if ( isset($basic["Default_VLAN"]) )
        {
            $VLAN=$basic["Default_VLAN"];
            $v4mask=$basic["Default_Localv4"];
            $v6mask=$basic["Default_Localv6"];
        }
    }
    $VLAN=makecol($VLAN,"number","manvlan",$serial++);
    $v4mask=makecol($v4mask,"text","manmask",$serial++);
    
    // No policies.  static description.
    $policies=makecolumn("");
    $desc=makecolumn("");

    $rowsource[$rownum]=makecolumn("config file");
    $indices[$rownum]= $authority;
    makerow($devtype,$controller,$VLAN,$v4mask,
       $policies,$desc,$rowsource[$rownum],$rownum++);
}

// OK.  Next check for unassigned VLANs.

$vlan_cursor=$vlan_collection->find(array('Owner' => array('$size' => 0)));

// there will be no authority, controller, or policies.

foreach ( $vlan_cursor as $vlan_entry ) {
    $devtype=makecolumn("");
    $controller=makecolumn('');
    $vlannum=$vlan_entry['VLAN_ID'];
    $VLAN=makecol($vlan_entry['VLAN_ID'],"number","vl",$serial++);
    $v4mask=makecol($vlan_entry['v4addrmask'],"text","vm",$serial++);
//    $v6mask=makecol($vlan_entry['v6addrmask'],"text","vm",$serial++); // not quite yet.
    $policies=makecolumn("");
    $desc=makecolumn("Unassigned VLAN");

    $rowsource[$rownum]=makecolumn("VLAN DB");
    $indices[$rownum]=$vlannum;
    makerow($devtype,$controller,$VLAN,$v4mask,
        $policies,$desc,$rowsource[$rownum],$rownum++);
}

// ok, build out index json
$index_json = makeindex_json($indices);

print "</tbody></table><p>";
if ( isset($_SESSION['update']) && ($_SESSION['update'] == 'true')) {
    $_SESSION['update']='false';
    print '<font color= "#da16cb">Database Updated</font>';

}

print '<br><br><input value="Update" type="submit" onClick="t_to_a(\'mtable\',\'json\')">';
print '<br><input name="json" id="json" hidden="true">';
print '<input name="indices" id="indices" value=\'' . 
        $index_json . '\' hidden="true">';
print "</p></form>";
?>