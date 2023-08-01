<template>
    <div class="">
        <div style="position: relative; left: 10px">
            <div v-for="i in tree">
                0x{{ i.tag.toString(16) }} {{ i.value }}
                <asn1-tree :tree="i.child" />
            </div>
        </div>
    </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from 'vue-property-decorator';
import Asn1Tree from "@/views/asn1/components/asn1Tree.vue";
@Component({
    name: 'asn1-tree',
    components: {Asn1Tree}
})
export default class ASN1TreeView extends Vue {
    @Prop({ default: () => [] })
    tree!: any[];

    mounted() {
        console.log(this.tree)
    }
}
</script>
<style lang="scss" scoped>
*{
    text-align: left;
}
</style>
