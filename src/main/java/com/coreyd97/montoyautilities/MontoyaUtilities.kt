package com.coreyd97.montoyautilities

import burp.api.montoya.MontoyaApi

class MontoyaUtilities(montoya: MontoyaApi) {

    init {
        MontoyaUtilities.montoya = montoya
    }

    companion object {
        lateinit var montoya: MontoyaApi
    }
}