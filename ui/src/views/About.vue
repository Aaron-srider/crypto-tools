<template>
    <div class="hello">
        <h1>About</h1>
        <el-card>
            <template #header>
                generate sm2 key
            </template>

            <el-button @click="generateSm2Key">gen sm2</el-button>
            public key
            <el-input type="textarea" readonly v-model="generatedPublicKey">
            </el-input>

            private key
            <el-input type="textarea" readonly v-model="generatedPrivate">
            </el-input>
        </el-card>
        <el-card>
            <template #header>
                generate cert
            </template>
            base64 pub key:
            <el-input v-model="pubKeyInput" @input="onUserInputPubKeyInput">
            </el-input>
            base64 cert data:
            <el-input type="textarea" autosize readonly v-model="certResult"></el-input>
        </el-card>
        <el-card>
            <template #header>
                extract cert
            </template>
            base64 cert data:
            <el-input v-model="inputCertForExtraction" @input="userInputForCertExtraction">
            </el-input>
            base64 pub key:
            <el-input type="textarea" readonly autosize v-model="extractedPubKey"></el-input>
        </el-card>
        <el-card>
            <template #header>bytes</template>

            <div class="flex">
                select type:
                <el-select v-model="userInputMode">
                    <el-option
                        v-for="item in ['auto', 'base64', 'hex', 'byteArray']"
                        :key="item"
                        :label="item"
                        :value="item"
                    ></el-option>
                </el-select>
                input:
                <el-input
                    type="textarea"
                    autosize
                    placeholder="Please input"
                    v-model="userInput"
                    @input="onInput"
                >
                </el-input>

                <div v-if="userInputType != null"> user input type:
                    <el-tag>{{ userInputType }}</el-tag>

                </div>


            </div>


            base64
            <el-input type="textarea" autosize v-model="formBase64"></el-input>
            hex
            <el-input type="textarea" autosize v-model="formHex"></el-input>
            byte array(java)
            <el-input type="textarea" autosize v-model="formByteArray"></el-input>
            char array(c)
            <el-input type="textarea" autosize v-model="formCharArray"></el-input>

            bytes square
            <el-input type="textarea" autosize v-model="bytesSquare"></el-input>
        </el-card>
    </div>
</template>

<script lang="ts">
import {Component, Vue} from 'vue-property-decorator';
import Client from "@/request/client";

@Component
export default class About extends Vue {

    onUserInputPubKeyInput() {
        if (this.pubKeyInput == null || this.pubKeyInput == "") {
            return
        }
        Client.cert(this.pubKeyInput).then(resp => {
            this.certResult = resp.data
        })
    }


    pubKeyInput: string | null = null
    certResult: string | null = null
    userInputMode: string = "auto"
    userInputType: string | null = null;
    userInput: string | null = null;
    formBase64: string | null = null;
    formHex: string | null = null;
    formByteArray: string | null = null;
    formCharArray: string | null = null;
    bytesSquare: string | null = null;
    generatedPublicKey: string | null = null;
    generatedPrivate: string | null = null;
    inputCertForExtraction: string | null = null
    extractedPubKey: string | null = null
    onInput() {
        if (this.userInput === null || this.userInput === "") {
            this.formBase64 = null;
            this.formHex = null;
            this.formByteArray = null;
            this.formCharArray = null;
            this.bytesSquare = null;
            return;
        }

        Client.getResult(encodeURIComponent(this.userInput), this.userInputMode).then(resp => {
            this.userInputType = resp.data?.data?.type
            this.formBase64 = resp.data?.data?.base64
            this.formHex = resp.data?.data?.hex
            this.formByteArray = resp.data?.data?.byteArray
            this.formCharArray = resp.data?.data?.charArray
            this.bytesSquare = resp.data?.data?.bytesSquare
        })
    }

    generateSm2Key() {
        Client.sm2key().then(resp => {
            this.generatedPublicKey = resp.data?.data?.publicKey
            this.generatedPrivate = resp.data?.data?.privateKey
        })
    }

    userInputForCertExtraction() {
        if(this.inputCertForExtraction == null)
        {
            return null;
        }

        this.extractPubKey(this.inputCertForExtraction)
    }


    extractPubKey(certBase64: string) {
      Client.certKey(certBase64).then(resp => {
          this.extractedPubKey = resp.data
      })
    }


}
</script>


<style lang="scss">
@import '~@/style/common-style.scss'
</style>
