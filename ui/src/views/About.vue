<template>
    <div class="hello">
        <h1>About</h1>
        <el-card>
            <template #header></template>

            <el-select v-model="userInputMode">
                <el-option
                    v-for="item in ['auto', 'base64', 'hex', 'byteArray']"
                    :key="item"
                    :label="item"
                    :value="item"
                ></el-option>
            </el-select>

            input
            <el-input
                type="textarea"
                autosize
                placeholder="Please input"
                v-model="userInput"
                @input="onInput"
            >
            </el-input>

            <el-tag>{{ userInputType }}</el-tag>


            base64
            <el-input type="textarea" autosize v-model="formBase64"></el-input>
            hex
            <el-input type="textarea" autosize v-model="formHex"></el-input>
            byte array(java)
            <el-input type="textarea" autosize v-model="formByteArray"></el-input>
            char array(c)
            <el-input type="textarea" autosize v-model="formCharArray"></el-input>

            bytes square
            <el-input type = "textarea" autosize v-model="bytesSquare"></el-input>
        </el-card>
    </div>
</template>

<script lang="ts">
import {Component, Vue} from 'vue-property-decorator';
import Client from "@/request/client";

@Component
export default class About extends Vue {
    userInputMode: string  = "auto"
    userInputType: string | null = null;
    userInput: string | null = null;
    formBase64: string | null = null;
    formHex: string | null = null;
    formByteArray: string | null = null;
    formCharArray: string | null = null;
    bytesSquare: string | null = null;

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
            this.userInputType = resp.data.type
            this.formBase64 = resp.data.base64
            this.formHex = resp.data.hex
            this.formByteArray = resp.data.byteArray
            this.formCharArray = resp.data.charArray
            this.bytesSquare = resp.data.bytesSquare
        })
    }


}
</script>
