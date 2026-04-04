//===-- OptionalityChecker.cpp - Optionality checker ----------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This checker tries to find violations in use of pointers to _Optional
// objects which cannot be detected by the type system alone. This requires
// detection of null pointer dereferences at the expression level, rather than
// at the level of simulated memory accesses (which is already implemented by
// other checkers).
//
// Such expressions include those which implicitly remove the _Optional
// qualifier from pointer targets without actually accessing the pointed-to
// object.
//
//===----------------------------------------------------------------------===//

#include "Iterator.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"

#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerHelpers.h"

#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/Path.h"

using namespace clang;
using namespace ento;

namespace {

class OptionalityChecker
    : public Checker<
          check::PreStmt<UnaryOperator>, check::PreStmt<BinaryOperator>,
          check::PreStmt<ArraySubscriptExpr>, check::PreStmt<MemberExpr>> {

  void verifyIncDec(CheckerContext &C, const Expr *E) const;
  void verifyAccess(CheckerContext &C, const Expr *E) const;
  void verifyCompare(CheckerContext &C, const Expr *L, const Expr *R) const;
  void verifyAdditive(CheckerContext &C, const Expr *L, const Expr *R) const;
  ExplodedNode *getNodeIfBug(CheckerContext &C, const Expr *E) const;

public:
  void checkPreStmt(const UnaryOperator *UO, CheckerContext &C) const;
  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;
  void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const;
  void checkPreStmt(const MemberExpr *ME, CheckerContext &C) const;

  CheckerNameRef CheckName;
  mutable std::unique_ptr<BugType> BT;

  const std::unique_ptr<BugType> &getBugType() const {
    if (!BT)
      BT.reset(new BugType(CheckName, "Optionality", categories::MemoryError));
    return BT;
  }

private:
  void reportBug(StringRef Msg, ExplodedNode *N, BugReporter &BR) const {
    const std::unique_ptr<BugType> &BT = getBugType();
    auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
    BR.emitReport(std::move(R));
  }
};

} // end anonymous namespace

void OptionalityChecker::checkPreStmt(const UnaryOperator *UO,
                                      CheckerContext &C) const {
  if (isa<CXXThisExpr>(UO->getSubExpr()))
    return;

  UnaryOperatorKind OK = UO->getOpcode();
  switch (OK) {
  case UO_Deref:
    verifyAccess(C, UO->getSubExpr());
    break;
  case UO_PreInc:
  case UO_PostInc:
  case UO_PreDec:
  case UO_PostDec:
    verifyIncDec(C, UO->getSubExpr());
    break;
  }
}

void OptionalityChecker::checkPreStmt(const BinaryOperator *BO,
                                      CheckerContext &C) const {
  BinaryOperatorKind OK = BO->getOpcode();

  if (OK == BO_PtrMemI) {
    verifyAccess(C, BO->getLHS());
  } else if (BinaryOperator::isRelationalOp(OK)) {
    verifyCompare(C, BO->getLHS(), BO->getRHS());
  } else if (BinaryOperator::isAdditiveOp(OK)) {
    verifyAdditive(C, BO->getLHS(), BO->getRHS());
  }
}

void OptionalityChecker::checkPreStmt(const ArraySubscriptExpr *ASE,
                                      CheckerContext &C) const {
  verifyAccess(C, ASE->getLHS());
}

void OptionalityChecker::checkPreStmt(const MemberExpr *ME,
                                      CheckerContext &C) const {
  if (!ME->isArrow() || ME->isImplicitAccess())
    return;

  verifyAccess(C, ME->getBase());
}

ExplodedNode *OptionalityChecker::getNodeIfBug(CheckerContext &C,
                                               const Expr *E) const {
  const Expr *SrcE = E->IgnoreParenImpCasts();

  if (!pointeeIsOptional(SrcE->getType()))
    return nullptr;

  ProgramStateRef State = C.getState();
  SVal Val = State->getSVal(SrcE, C.getLocationContext());

  if (SymbolRef Sym = Val.getAsSymbol()) {
    SVal SymVal = C.getSValBuilder().makeSymbolVal(Sym);

    if (State->isNonNull(SymVal).isConstrainedTrue())
      return nullptr;
  }

  // Convert lvalue to value if necessary (e.g. for unary ++)
  if (auto Location = Val.getAs<Loc>())
    Val = State->getSVal(*Location);

  auto DefOrUnknown = Val.getAs<DefinedOrUnknownSVal>();
  if (!DefOrUnknown)
    return nullptr;

  if (State->isNonNull(*DefOrUnknown).isConstrainedTrue())
    return nullptr;

  return C.generateErrorNode(State);
}

void OptionalityChecker::verifyIncDec(CheckerContext &C, const Expr *E) const {
  ExplodedNode *const N = getNodeIfBug(C, E);
  if (!N)
    return;

  BugReporter &BR = C.getBugReporter();
  // Do not suppress errors on defensive code paths, because dereferencing
  // a nullable pointer is always an error.
  reportBug("Pointer to _Optional object is used by an increment or decrement "
            "operator without a preceding check for null",
            N, BR);
}

void OptionalityChecker::verifyAccess(CheckerContext &C, const Expr *E) const {
  ExplodedNode *const N = getNodeIfBug(C, E);
  if (!N)
    return;

  BugReporter &BR = C.getBugReporter();
  // Do not suppress errors on defensive code paths, because dereferencing
  // a nullable pointer is always an error.
  reportBug("Pointer to _Optional object is dereferenced without a preceding "
            "check for null",
            N, BR);
}

void OptionalityChecker::verifyCompare(CheckerContext &C, const Expr *L,
                                       const Expr *R) const {
  ExplodedNode *N = getNodeIfBug(C, L);
  if (!N)
    N = getNodeIfBug(C, R);

  if (!N)
    return;

  BugReporter &BR = C.getBugReporter();
  // Do not suppress errors on defensive code paths, because dereferencing
  // a nullable pointer is always an error.
  reportBug("Pointer to _Optional object is used by a relational operator "
            "without a preceding check for null",
            N, BR);
}

void OptionalityChecker::verifyAdditive(CheckerContext & C, const Expr *L,
                                        const Expr *R) const {
  ExplodedNode *N = getNodeIfBug(C, L);
  if (!N)
    N = getNodeIfBug(C, R);

  if (!N)
    return;

  BugReporter &BR = C.getBugReporter();
  // Do not suppress errors on defensive code paths, because dereferencing
  // a nullable pointer is always an error.
  reportBug("Pointer to _Optional object is used by an additive operator "
            "without a preceding check for null",
            N, BR);
}

void ento::registerOptionalityChecker(CheckerManager &mgr) {
  mgr.registerChecker<OptionalityChecker>();
  OptionalityChecker *checker = mgr.getChecker<OptionalityChecker>();
  checker->CheckName = mgr.getCurrentCheckerName();
}

bool ento::shouldRegisterOptionalityChecker(const CheckerManager &mgr) {
  return true;
}
