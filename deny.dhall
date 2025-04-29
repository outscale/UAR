 -- import common deny file
let common = https://git.scaledome.io/tools/packages-deny-conf-files/raw/rust/deny.dhall

-- update common record keys and return it
in common 
    -- examples of merging common values with custom one
    -- with licenses.exceptions = common.licenses.exceptions # [{ 
        -- crate = "webpki-roots",
        -- allow = ["MPL-2.0"] -- allowed because no source modification
    -- }]
    -- with licenses.clarify = common.licenses.clarify # [{
        -- crate = "webpki",
        -- expression = "ISC",
        -- to get the hash value below: start with hash = 0x00, run cargo deny and copy the expected value
        -- license-files = [{path = "LICENSE",hash = 0x001c7e6c}]
    -- }]
