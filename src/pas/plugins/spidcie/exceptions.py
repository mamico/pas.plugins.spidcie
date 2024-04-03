class InvalidTrustchain(Exception):
    pass


class UnknownKid(Exception):
    pass


class TrustchainMissingMetadata(ValueError):
    pass


class MetadataDiscoveryException(ValueError):
    pass


class MissingJwksClaim(ValueError):
    pass


class MissingTrustMark(ValueError):
    pass


class TrustAnchorNeeded(ValueError):
    pass


class InvalidEntityConfiguration(ValueError):
    pass


class InvalidRequiredTrustMark(ValueError):
    pass
