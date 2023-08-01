<template>
    <div class="">
        hello
        <asn1-tree :tree="parse()" />
    </div>
</template>

<script lang="ts">
import { Component, Vue } from 'vue-property-decorator';
import Asn1Tree from '@/views/asn1/components/asn1Tree.vue';
import { a1parse } from '@/ts/asn1Parser';

@Component({
    components: { Asn1Tree },
})
export default class ASN1View extends Vue {
    hex_data =
        '30820222308201c8a00302010202060189b0776613300a06082a811ccf55018375300f310d300b060355040a0c0474657374301e170d3233303830313039333932325a170d3333303830313039333932325a300f310d300b060355040a0c0474657374308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff30440420fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc042028e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e9304410432c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0022100fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d5412302010103420004d043231fe6b93eaa8b5b9d7eecb31ba857f41472f70b18efd8d30150b955f234de9db501ab55f9463748c65e409c518a78aee6a1a5d12ac3872284158b63d29ba3343032300b0603551d0f0404030203e8301206096086480186f842010d04050c0363636d300f0603551d130101ff040530030101ff300a06082a811ccf55018375034800304502207b1e031eaa30f3dfe015dd1922fd3c0ddd8334339c7e24077e80b58fac0dc27b022100aaf35751596d8319f020d03dc49e68f53abc690ba66eb9eaaf3927ef0a348b9d';

    parse() {
        console.log(this.hex_data);
        console.log(a1parse(this.hex_data));
        return a1parse(this.hex_data);
    }
}
</script>
<style lang="scss" scoped></style>
