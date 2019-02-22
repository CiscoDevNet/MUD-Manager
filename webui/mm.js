

/* take a row element, access the columns, and generate JSON array.
 */
function mkcol(ind,cells) {
    
    var k='[ ';			// start array
    var i;
    var end = cells.length - 1;	// skip checkbox at the end.

    for (i=0; i< end; i++) {
	if ( cells[i].firstElementChild != null ) { // input or span
	    var inp=cells[i].firstElementChild;
	    
	    if ( inp.localName == "input" ) { // null for input
		k= k + '"' + inp.value + '",';
	    } else { // is span
		k= k + '"' + inp.innerText + '",';
	    }
	} else {
	    k= k + '"' + cells[i].innerText + '",'; // add element in quotes
	}
    }
    k= k + ind +  ' ]';		// close array
    return k;
}


/* make an array of elements that are selected. */

function t_to_a(tid,json) {
    var i;
    var rows=document.getElementById(tid).rows;
    var json=document.getElementById(json);
    var res='[ ';
    var addcomma='';
    for (i=1;i < rows.length; i++) { // skip the header
	var last = rows[i].cells.length - 1;
	var thecell=rows[i].cells[last].firstElementChild;
	if ( thecell.type == 'checkbox' && 
	     thecell.checked == true ) {
	    if ( addcomma == ',' ) {
		res = res + addcomma;
	    }
	    res = res +  mkcol(i-1,rows[i].cells);
	    addcomma=',';
	}
    }
    res = res + ' ]';
    json.value = res;
    return;
}


function isEditable(colnum,source) {
    
    switch(colnum) {
    case 1:
	if ( source == 'MUD state') {
	    return(true);
	} else {
	    return(false);
	}
    case 2: // VLAN
    case 3:
	if ( source != 'config file' ) {
	    return(true);
	}
    default: 
	return(false);
    }
}
	
function toggleEditable(mybutton,idx) {

    if( mybutton.checked == true ) {
	makeEditable(mybutton);
    } else {
	makeUneditable(mybutton);
    }
}

// copy any innerText into the value of an input.  Cycle through
// each element in a row and test if editable first.
// find the row of the checkbox that is checked.  We'll rely on this
// for this purpose. 

function makeEditable(mybutton) {
    var row=mybutton.parentNode.parentNode;
    var source=row.cells[5].innerText;
    var i;

    // we need the source.  this will be in cell 5.
    
    for (i=0; i<row.childElementCount; i++) {
	if ( isEditable(i,source) ) { // establish a new input element.
	    var newin=document.createElement("Input");
	    if ( i == 2 ) { // VLAN
		newin.setAttribute("type","number");
		newin.setAttribute("max",1024);
		newin.setAttribute("required",true);
		newin.setAttribute("min",0);
		newin.setAttribute("size",4);
		newin.setAttribute("maxlength",4);
		newin.setAttribute("value",Number(row.cells[i].innerText));
	    } else {
		newin.setAttribute("value",row.cells[i].innerText);
	    }

	    if ( i == 3 && row.cells[2].innerText != '' ) {
		newin.setAttribute("required",true);
	    }
	    // clear the innerHTML in the current cell.
	    row.cells[i].saveInnerHTML=row.cells[i].innerHTML;
	    row.cells[i].saveInnerText=row.cells[i].innerText;
	    row.cells[i].innerHTML='';
	    row.cells[i].innerText='';
	    row.cells[i].appendChild(newin);
	}
    }
}

// Now we need a function to make something uneditable.

function makeUneditable(mybutton) {
    var row=mybutton.parentNode.parentNode;
    var i;

    for (i=0; i<row.childElementCount-1; i++) {
	if (row.cells[i].firstElementChild != null) {
	    if ( row.cells[i].firstElementChild.localName == "input" ) {
		// just nuke the element and restore visibility.
		// get old values;
		var oldHTML = row.cells[i].saveInnerHTML;
		row.cells[i].removeChild(row.cells[i].firstElementChild);
		row.cells[i].innerHTML= oldHTML;
	    }
	}
    }
}
