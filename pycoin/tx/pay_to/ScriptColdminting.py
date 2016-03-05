from ..script import tools

from ... import encoding

from ...networks import pay_to_script_prefix_for_netcode, address_prefix_for_netcode
from ...serialize import b2h

from .ScriptType import ScriptType


class ScriptColdminting(ScriptType):
    TEMPLATE = tools.compile("OP_DUP OP_HASH160 OP_MINT OP_IF OP_PUBKEYHASH OP_ELSE OP_PUBKEYHASH OP_ENDIF OP_EQUALVERIFY OP_CHECKSIG")

    def __init__(self, mint_hash160, spend_hash160, use_uncompressed=False):
        self._mint_hash160 = mint_hash160
        self._spend_hash160 = spend_hash160
        self._script = None

    @classmethod
    def from_script(cls, script):
        r = cls.match(script)
        if r:
            hash160 = r['PUBKEYHASH_LIST']
            s = cls(mint_hash160=hash160[0], spend_hash160=hash160[1])
            return s
        raise ValueError("bad script")

    def solve(self, **kwargs):
        """
        The kwargs required depend upon the script type.
        hash160_lookup:
            dict-like structure that returns a secret exponent for a hash160
        sign_value:
            the integer value to sign (derived from the transaction hash)
        signature_type:
            usually SIGHASH_ALL (1)
        """
        # we need a hash160 => secret_exponent lookup
        db = kwargs.get("hash160_lookup")
        if db is None:
            raise SolvingError("missing hash160_lookup parameter")

        sign_value = kwargs.get("sign_value")
        signature_type = kwargs.get("signature_type")

        result = db.get(self._spend_hash160) # Spending only

        if result is None:
            raise SolvingError("missing spending key")

        secret_exponent, public_pair, compressed = result
        binary_signature = self._create_script_signature(secret_exponent, sign_value, signature_type)
        pubkey_sec = encoding.public_pair_to_sec(public_pair)

        script = "%s %s %s" % (b2h(binary_signature), b2h(pubkey_sec), b2h(self.script()))
        solution = tools.compile(script)
        return solution

    def script(self):
        if self._script is None:
            # create the script
            STANDARD_SCRIPT_OUT = "OP_DUP OP_HASH160 OP_MINT OP_IF %s OP_ELSE %s OP_ENDIF OP_EQUALVERIFY OP_CHECKSIG"
            script_text = STANDARD_SCRIPT_OUT % (b2h(self._mint_hash160),
                                                 b2h(self._spend_hash160))
            self._script = tools.compile(script_text)
        return self._script

    def info(self, netcode="NEU"):
        address_script_prefix = pay_to_script_prefix_for_netcode(netcode)
        address_prefix        = address_prefix_for_netcode(netcode)
        hash160s   = encoding.hash160(self.script())
        address    = encoding.hash160_sec_to_bitcoin_address(hash160s, address_prefix=address_script_prefix)
        mint_addr  = encoding.hash160_sec_to_bitcoin_address(self._mint_hash160, address_prefix=address_prefix)
        spend_addr = encoding.hash160_sec_to_bitcoin_address(self._spend_hash160, address_prefix=address_prefix)
        return dict(type="coldminting", address=address, hash160=hash160s,
                    script=self._script, address_prefix=address_prefix,
                    minting_address=mint_addr, spending_address=spend_addr,
                    summary=address)

    def __repr__(self):
        info = self.info()
        return "<Script: coldminting minting: %s, spending: %s>" % (
                info['minting_address'], info['spending_address'])
