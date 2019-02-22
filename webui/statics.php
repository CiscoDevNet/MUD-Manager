<?php

$begin=<<< BEGIN
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html><head><title>MUD Manager Configuration</title>
<script type="text/javascript" src="mm.js"></script>
<link rel="stylesheet" href="style.css">
<meta http-equiv="content-type" content="text/html; charset=ISO-8859-1"> 
<meta name="author" content="Eliot Lear"></head>
<body>
<div align="center"><h1>MUD Manager Configuration</h1></div>
<p>This is the MUD Manager Configuration Screen.  Click "edit" on those
   rows you wish to change.</p>

BEGIN;

$table_front=<<< TABLEFRONT
<form method='POST' action='mud-edit.php'>
<table id='mtable' border='1'><col width='80'><col width='80'><col width\
='120'><col width='160'><col width='160'><col width='80'><col width='180'><tbody><tr><th>Device Type</th><th>Controller</th><th>VLAN</th><th>Net Mask</th><th>Policies</th><th>Source</th><th>Description</th><th>Edit?</th></tr>

TABLEFRONT;

$pbegin=<<< PBEGIN
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html><head><title>Policies</title>
<script type="text/javascript" src="mm.js" defer></script>
<meta http-equiv="content-type" content="text/html; charset=ISO-8859-1"> <meta name="author" content="Eliot Lear"></head>
    <body style="color: rgb(0, 0, 0); background-color: rgb(255, 255, 255);" link="#0000ee" alink="#0000ee" vlink="#551a8b" onload="eraseCookies()">
PBEGIN;
