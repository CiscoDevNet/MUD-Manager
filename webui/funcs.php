<?php

/*
 * this function returns a string wrapped in an input function and a <td>.
 * The type can be text or a number.
 */

function makecol($value,$type = 'text', $name, $serial) {
    
/*    $string = '<td><input name="' . $name . $serial . '" type="' . $type . '"';
    if ($type = "number") {
        $string = $string . ' min="0" max="1024" ';
    }
    $string = $string . 'value="' . $value . '"></td>';
    return($string);*/
    return makecolumn($value);
}

function makecolumn($string) 
{
    return("<td>" . $string . '</td>');
}

function makerow($devtype,$controller,$VLAN,$v4mask,$policies,
    $desc,$src,$rownum) {
    print "<tr>";
    print $devtype . $controller .  $VLAN . $v4mask . 
        $policies . $src . $desc ;
    print '<td><input type="checkbox" name="rowcheck' . $rownum . 
        '" onchange="toggleEditable(this);"></td>';
    print "</tr>";
}




/*
 * Read in config
 *
 */

function read_config($file,&$basic,&$mans,&$vlans,&$defaults) {

    if ( ($conf_json=file_get_contents($file)) == FALSE ) {
        print "<br>No config file<br>\n";
    }

    $top=json_decode($conf_json, $assoc = TRUE);
    if ( json_last_error() != JSON_ERROR_NONE ) {
        print "JSON error";
        exit;
    }

    foreach($top as $key => $value) {
        switch($key) {
        case "VLANs":
            $vlans=$value;
            break;
        case "Manufacturers":
            $mans=$value;
            break;
        case "DefaultACL":
            $defaults=$value;
            break;
        default:
            $basic[$key]=$value;
        }
    }

    if (! isset($basic['Default_VLAN'] )) {
        $basic['Default_VLAN']='';
        $basic['Default_Localv4']='';
    }
}

function init_database(&$client,&$mud,&$vlan,&$policies) 
{
    $client = new MongoDB\Client("mongodb://localhost:27017");
    $mud = $client->mud_manager->mudfile;
    $vlan = $client->mud_manager->vlans;
    $policies = $client->mud_manager->mud_policies;
}

// return a JSON array of the indices in the array

function makeindex_json($indices) {
    
    $res= '[ ';
    
    for ( $i = 0 ; $i < sizeof($indices) ; $i++ ) {
        $res = $res . ' "' . $indices[$i] . '"';
        if ($i < (sizeof($indices) - 1)) {
            $res = $res . ', ';
        }
    }

    $res = $res . ' ]';
    return $res;
}
