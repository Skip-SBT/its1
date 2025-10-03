export class IntegrityError extends Error {
    constructor(msg = "Integrity check failed") { super(msg); this.name = "IntegrityError"; }
}
export class FormatError extends Error {
    constructor(msg = "Invalid container format") { super(msg); this.name = "FormatError"; }
}
export class PaddingError extends Error {
    constructor(msg = "Invalid padding") { super(msg); this.name = "PaddingError"; }
}
