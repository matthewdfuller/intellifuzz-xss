<?php

function remove_semi_colon($in) {
    return str_replace(";", "", $in);
}

function remove_script($in) {
    return str_replace("<script>", "", $in);
}

?>