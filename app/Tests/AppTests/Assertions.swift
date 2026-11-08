import Testing

// Small helpers, so the tests read the same with or without the Xcode test framework.

func XCTAssertEqual<T: Equatable>(
    _ a: @autoclosure () throws -> T, _ b: @autoclosure () throws -> T, _ message: String = "",
    sourceLocation: SourceLocation = #_sourceLocation
) {
    do {
        let (left, right) = (try a(), try b())
        if left != right {
            Issue.record("\(left) is not \(right) \(message)", sourceLocation: sourceLocation)
        }
    } catch {
        Issue.record("threw \(error) \(message)", sourceLocation: sourceLocation)
    }
}

func XCTAssertThrowsError<T>(
    _ body: @autoclosure () throws -> T, _ message: String = "",
    sourceLocation: SourceLocation = #_sourceLocation
) {
    do {
        _ = try body()
        Issue.record("did not throw \(message)", sourceLocation: sourceLocation)
    } catch {}
}

func XCTAssertNil<T>(_ value: T?, sourceLocation: SourceLocation = #_sourceLocation) {
    if value != nil { Issue.record("expected nil", sourceLocation: sourceLocation) }
}

func XCTAssertNotNil<T>(_ value: T?, sourceLocation: SourceLocation = #_sourceLocation) {
    if value == nil { Issue.record("unexpected nil", sourceLocation: sourceLocation) }
}

func XCTAssertFalse(_ value: Bool, sourceLocation: SourceLocation = #_sourceLocation) {
    if value { Issue.record("expected false", sourceLocation: sourceLocation) }
}

func XCTAssertGreaterThan(_ a: Int, _ b: Int, sourceLocation: SourceLocation = #_sourceLocation) {
    if a <= b { Issue.record("\(a) is not above \(b)", sourceLocation: sourceLocation) }
}

func XCTUnwrap<T>(_ value: T?, sourceLocation: SourceLocation = #_sourceLocation) throws -> T {
    try #require(value, sourceLocation: sourceLocation)
}
