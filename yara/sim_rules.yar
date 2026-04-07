rule SIM_Print_Rule {
    strings:
        $a = "SIM_PRINT"
    condition:
        $a
}

rule SIM_Dropper_Rule {
    strings:
        $b = "SIM_DROPPER"
    condition:
        $b
}

rule SIM_Net_Rule {
    strings:
        $c = "SIM_NET"
    condition:
        $c
}


