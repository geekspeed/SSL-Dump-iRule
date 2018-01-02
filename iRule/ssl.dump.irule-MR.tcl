when CLIENT_ACCEPTED {
    TCP::collect
}
when CLIENT_DATA {
    binary scan [TCP::payload] cSS rtype sslver rlen

    if { $rtype == 22 } {

        #Collect rest of the record if necessary
        if { [TCP::payload length] < $rlen } {
            TCP::collect $rlen
        }

        #skip record header and random data
        set field_offset 43

        #set the offset
        binary scan [TCP::payload] @${field_offset}c sessID_len
        set field_offset [expr {$field_offset + 1 + $sessID_len}]

        #Get cipherlist length
        binary scan [TCP::payload] @${field_offset}S cipherList_len

        #Get ciphers, separate into a list of elements
        set field_offset [expr {$field_offset + 2}]
        set cipherList_len [expr {$cipherList_len * 2}]
        binary scan [TCP::payload] @${field_offset}H${cipherList_len} cipherlist

        set clist [list]
        for { set i 0 } { $i < [string length $cipherlist] } { incr i 4 } {
            lappend clist [string range $cipherlist $i [expr $i + 3]]
        }
        set cliststr [join $clist ","]
        set tmpName = [string range [virtual name] 8 end ]
        log local0. "|$tmpName|[IP::client_addr]|$cliststr"
    }
    TCP::release
}
when CLIENTSSL_HANDSHAKE {
    set tmpName = [string range [virtual name] 8 end]
    log local0. "|$tmpName|[IP::client_addr]||[SSL::cipher name]"
    if { ( [SSL::cipher version] contains "SSL" ) or 
         ( [SSL::cipher name] contains "DES" ) or 
         ( [SSL::cipher name] contains "RC4" ) or
         ( [SSL::cipher name] ends_with "SHA" ) or
         ( [SSL::cipher bits] < 128 ) } then {
         set invalid_ssl 1
    } else {
        set invalid_ssl 0
    }

}
when HTTP_REQUEST {
    if { $invalid_ssl } then {
        set tmpName = [string range [virtual name] 8 end]
        log local0. "|$tmpName|[IP::client_addr]|||[SSL::cipher version], [SSL::cipher name]|[SSL::cipher bits]|[HTTP::header value "User-Agent"]"
        set invalid_ssl 0
    }
}
