//! Bounded lexical query-block plan for the served read proof.

use super::*;
use crate::resolver::{MergedJoin, QueryBlock, QueryBlockId, QueryBlockKind};
use std::collections::{HashMap, HashSet};

pub const MAX_QUERY_BLOCKS: usize = 128;
pub const MAX_BLOCK_DEPTH: usize = 32;
pub const MAX_PLANNED_RELATIONS: usize = 256;
const MAX_PLANNED_VALUES: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanMismatch {
    RelationPlanMismatch,
    RelationPlanCapExceeded,
    UnsupportedShape,
    RecursiveCte,
}

impl PlanMismatch {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RelationPlanMismatch => "relation_plan_mismatch",
            Self::RelationPlanCapExceeded => "relation_plan_cap_exceeded",
            Self::UnsupportedShape => "query scope is not exactly representable",
            Self::RecursiveCte => "recursive CTE dependency is not supported",
        }
    }
}

fn normalized_part(part: &RawNamePart) -> String {
    match part.quoting {
        QuoteSemantics::Quoted => part.text.clone(),
        QuoteSemantics::Unquoted => part.text.to_ascii_uppercase(),
    }
}

fn object_key(object: &ObjectRef) -> (Option<String>, String) {
    (object.schema.clone(), object.name.clone())
}

/// Independent recursive collector must see exactly the same catalog targets.
/// The collector retains source spelling; both sides come from the same parsed
/// statement, so an unequal spelling is itself a refusal, including quotes.
pub fn planned_relations_match_base_objects(
    plan: &SemanticReadPlan,
    base_objects: &[ObjectRef],
) -> Result<(), PlanMismatch> {
    let planned: HashSet<_> = plan
        .relations
        .iter()
        .map(|name| {
            let parts = &name.parts;
            let last = parts.last().expect("planner emits nonempty names");
            let schema = (parts.len() > 1).then(|| parts[parts.len() - 2].text.clone());
            (schema, last.text.clone())
        })
        .collect();
    let collected: HashSet<_> = base_objects.iter().map(object_key).collect();
    if planned == collected {
        Ok(())
    } else {
        Err(PlanMismatch::RelationPlanMismatch)
    }
}

struct QueryFrame {
    block: QueryBlockId,
    direct_select: Option<usize>,
    ctes: HashSet<String>,
    cte_order: HashMap<String, usize>,
    active_cte: Option<String>,
}

struct BlockWalker {
    blocks: Vec<QueryBlock>,
    query_frames: Vec<QueryFrame>,
    select_blocks: Vec<QueryBlockId>,
    builtin_contexts: Vec<BuiltinIdentifierContext>,
    query_kinds: HashMap<usize, QueryBlockKind>,
    derived_aliases: HashMap<usize, (QueryBlockId, RawNamePart)>,
    branch_selects: HashSet<usize>,
    order_alias_expressions: HashSet<*const Expr>,
    metric_expressions: Vec<*const Expr>,
    model_expressions: Vec<*const Expr>,
    relation_count: usize,
    value_count: usize,
}

impl BlockWalker {
    fn new() -> Self {
        Self {
            blocks: Vec::new(),
            query_frames: Vec::new(),
            select_blocks: Vec::new(),
            builtin_contexts: Vec::new(),
            query_kinds: HashMap::new(),
            derived_aliases: HashMap::new(),
            branch_selects: HashSet::new(),
            order_alias_expressions: HashSet::new(),
            metric_expressions: Vec::new(),
            model_expressions: Vec::new(),
            relation_count: 0,
            value_count: 0,
        }
    }

    fn current_block(&self) -> Option<QueryBlockId> {
        self.select_blocks
            .last()
            .copied()
            .or_else(|| self.query_frames.last().map(|f| f.block))
    }

    fn add_block(
        &mut self,
        parent: Option<QueryBlockId>,
        kind: QueryBlockKind,
    ) -> Result<QueryBlockId, PlanMismatch> {
        if self.blocks.len() >= MAX_QUERY_BLOCKS {
            return Err(PlanMismatch::RelationPlanCapExceeded);
        }
        let mut depth = 0;
        let mut ancestor = parent;
        while let Some(id) = ancestor {
            depth += 1;
            ancestor = self.blocks[id.0].parent;
        }
        if depth >= MAX_BLOCK_DEPTH {
            return Err(PlanMismatch::RelationPlanCapExceeded);
        }
        let id = QueryBlockId(self.blocks.len());
        self.blocks.push(QueryBlock {
            id,
            parent,
            kind,
            relations: Vec::new(),
            cte_refs: Vec::new(),
            cte_source_aliases: Vec::new(),
            correlated_outer_refs: Vec::new(),
            values: Vec::new(),
            statement_scope: StatementScope::default(),
            projected_columns: Vec::new(),
            cte_definitions: Vec::new(),
            derived_sources: Vec::new(),
        });
        Ok(id)
    }

    fn mark_set_branches(&mut self, body: &SetExpr) -> Result<(), PlanMismatch> {
        match body {
            SetExpr::Select(_) => Ok(()),
            SetExpr::SetOperation { left, right, .. } => {
                self.mark_branch(left)?;
                self.mark_branch(right)
            }
            SetExpr::Query(query) => {
                self.query_kinds.insert(
                    query.as_ref() as *const Query as usize,
                    QueryBlockKind::SetOperationBranch,
                );
                Ok(())
            }
            _ => Err(PlanMismatch::UnsupportedShape),
        }
    }

    fn mark_branch(&mut self, body: &SetExpr) -> Result<(), PlanMismatch> {
        match body {
            SetExpr::Select(select) => {
                self.branch_selects.insert(select_id(select));
                Ok(())
            }
            SetExpr::SetOperation { left, right, .. } => {
                self.mark_branch(left)?;
                self.mark_branch(right)
            }
            SetExpr::Query(query) => {
                self.query_kinds.insert(
                    query.as_ref() as *const Query as usize,
                    QueryBlockKind::SetOperationBranch,
                );
                Ok(())
            }
            _ => Err(PlanMismatch::UnsupportedShape),
        }
    }

    fn is_cte(&self, name: &RawName) -> bool {
        if name.parts.len() != 1 {
            return false;
        }
        let key = normalized_part(&name.parts[0]);
        self.query_frames
            .iter()
            .rev()
            .any(|frame| frame.ctes.contains(&key))
    }

    fn add_relation(&mut self, relation: StatementRelation) -> Result<(), PlanMismatch> {
        let block_id = self.current_block().ok_or(PlanMismatch::UnsupportedShape)?;
        if relation.name.db_link.is_some() {
            return Err(PlanMismatch::UnsupportedShape);
        }
        let is_cte = self.is_cte(&relation.name);
        let block = &mut self.blocks[block_id.0];
        if is_cte {
            let key = normalized_part(&relation.name.parts[0]);
            for frame in self.query_frames.iter().rev() {
                let Some(active) = frame.active_cte.as_deref() else {
                    continue;
                };
                if active == key {
                    return Err(PlanMismatch::RecursiveCte);
                }
                if let Some(scope) = self.query_frames.iter().rev().find(|scope| {
                    scope.cte_order.contains_key(active) && scope.cte_order.contains_key(&key)
                }) && scope.cte_order[&key] >= scope.cte_order[active]
                {
                    return Err(PlanMismatch::RecursiveCte);
                }
                break;
            }
            block.cte_refs.push(relation.name.parts[0].clone());
            if let Some(alias) = &relation.alias {
                block
                    .cte_source_aliases
                    .push((relation.name.parts[0].clone(), alias.clone()));
            }
            block
                .statement_scope
                .common_table_expressions
                .push(relation.name.parts[0].clone());
        } else {
            self.relation_count += 1;
            if self.relation_count > MAX_PLANNED_RELATIONS {
                return Err(PlanMismatch::RelationPlanCapExceeded);
            }
            block.relations.push(relation.name.clone());
            block.statement_scope.relations.push(relation.clone());
        }
        if let Some(alias) = relation.alias {
            block.statement_scope.aliases.push(alias);
        }
        Ok(())
    }
}

impl Visitor for BlockWalker {
    type Break = PlanMismatch;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        self.order_alias_expressions
            .extend(direct_select_order_alias_expressions(query));
        let pointer = query as *const Query as usize;
        let kind = if self.query_frames.is_empty() {
            QueryBlockKind::Root
        } else {
            match self.query_kinds.remove(&pointer) {
                Some(kind) => kind,
                None => return ControlFlow::Break(PlanMismatch::UnsupportedShape),
            }
        };
        let parent = self.current_block();
        let block = match self.add_block(parent, kind.clone()) {
            Ok(block) => block,
            Err(error) => return ControlFlow::Break(error),
        };
        if let Some(parent) = parent {
            if let QueryBlockKind::CteDefinition(part) = &kind {
                self.blocks[parent.0]
                    .cte_definitions
                    .push((part.clone(), block));
            }
            if let Some((owner, alias)) = self.derived_aliases.remove(&pointer) {
                self.blocks[owner.0].derived_sources.push((alias, block));
            }
        }
        let mut ctes = self
            .query_frames
            .last()
            .map(|f| f.ctes.clone())
            .unwrap_or_default();
        let mut cte_order = HashMap::new();
        if let Some(with) = &query.with {
            if with.recursive {
                return ControlFlow::Break(PlanMismatch::RecursiveCte);
            }
            for (position, cte) in with.cte_tables.iter().enumerate() {
                let part = raw_name_part(&cte.alias.name);
                let key = normalized_part(&part);
                if !ctes.insert(key) {
                    return ControlFlow::Break(PlanMismatch::RecursiveCte);
                }
                cte_order.insert(normalized_part(&part), position);
                self.query_kinds.insert(
                    cte.query.as_ref() as *const Query as usize,
                    QueryBlockKind::CteDefinition(part),
                );
            }
        }
        if let Err(error) = self.mark_set_branches(query.body.as_ref()) {
            return ControlFlow::Break(error);
        }
        let direct_select = match query.body.as_ref() {
            SetExpr::Select(select) => Some(select_id(select)),
            _ => None,
        };
        self.query_frames.push(QueryFrame {
            block,
            direct_select,
            ctes,
            cte_order,
            active_cte: if let QueryBlockKind::CteDefinition(part) = kind {
                Some(normalized_part(&part))
            } else {
                None
            },
        });
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<Self::Break> {
        self.query_frames.pop();
        ControlFlow::Continue(())
    }

    fn pre_visit_select(&mut self, select: &Select) -> ControlFlow<Self::Break> {
        let supported_hierarchy = select.connect_by.is_empty()
            || (select.connect_by.len() == 1
                && matches!(select.from.as_slice(), [source] if source.joins.is_empty() && simple_statement_relation(&source.relation).is_some()));
        if select.into.is_some()
            || !supported_hierarchy
            || !select.lateral_views.is_empty()
            || select.prewhere.is_some()
        {
            return ControlFlow::Break(PlanMismatch::UnsupportedShape);
        }
        let Some(frame) = self.query_frames.last() else {
            return ControlFlow::Break(PlanMismatch::UnsupportedShape);
        };
        let block = if frame.direct_select == Some(select_id(select)) {
            frame.block
        } else if self.branch_selects.contains(&select_id(select)) {
            match self.add_block(Some(frame.block), QueryBlockKind::SetOperationBranch) {
                Ok(id) => id,
                Err(error) => return ControlFlow::Break(error),
            }
        } else {
            return ControlFlow::Break(PlanMismatch::UnsupportedShape);
        };
        self.select_blocks.push(block);
        self.builtin_contexts
            .push(BuiltinIdentifierContext::from_select(select));
        // Only a single plain pair has unambiguous merge ownership. Larger
        // join trees still collect every relation but do not grant a merge.
        for source in &select.from {
            let [join] = source.joins.as_slice() else {
                continue;
            };
            let (Some(left), Some(right)) = (
                simple_statement_relation(&source.relation),
                simple_statement_relation(&join.relation),
            ) else {
                continue;
            };
            let constraint = match &join.join_operator {
                sqlparser::ast::JoinOperator::Join(c)
                | sqlparser::ast::JoinOperator::Inner(c)
                | sqlparser::ast::JoinOperator::Left(c)
                | sqlparser::ast::JoinOperator::LeftOuter(c)
                | sqlparser::ast::JoinOperator::Right(c)
                | sqlparser::ast::JoinOperator::RightOuter(c)
                | sqlparser::ast::JoinOperator::FullOuter(c) => c,
                _ => continue,
            };
            let using_columns = match constraint {
                sqlparser::ast::JoinConstraint::Natural => None,
                sqlparser::ast::JoinConstraint::Using(names) => {
                    let mut columns = Vec::new();
                    for name in names {
                        let [part] = name.0.as_slice() else {
                            return ControlFlow::Break(PlanMismatch::UnsupportedShape);
                        };
                        let Some(ident) = part.as_ident() else {
                            return ControlFlow::Break(PlanMismatch::UnsupportedShape);
                        };
                        columns.push(raw_name_part(ident));
                    }
                    if columns.is_empty() {
                        return ControlFlow::Break(PlanMismatch::UnsupportedShape);
                    }
                    Some(columns)
                }
                _ => continue,
            };
            self.blocks[block.0]
                .statement_scope
                .merged_joins
                .push(MergedJoin {
                    left,
                    right,
                    using_columns,
                });
        }
        for item in &select.projection {
            let projected = match item {
                sqlparser::ast::SelectItem::ExprWithAlias { alias, .. } => {
                    Some(raw_name_part(alias))
                }
                sqlparser::ast::SelectItem::UnnamedExpr(Expr::Identifier(ident)) => {
                    Some(raw_name_part(ident))
                }
                sqlparser::ast::SelectItem::UnnamedExpr(Expr::CompoundIdentifier(parts)) => {
                    parts.last().map(raw_name_part)
                }
                _ => None,
            };
            if let Some(column) = projected {
                self.blocks[block.0].projected_columns.push(column);
            }
        }
        ControlFlow::Continue(())
    }

    fn post_visit_select(&mut self, _select: &Select) -> ControlFlow<Self::Break> {
        self.select_blocks.pop();
        self.builtin_contexts.pop();
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<Self::Break> {
        match factor {
            TableFactor::Table { args: None, .. } => {
                let Some(relation) = simple_statement_relation(factor) else {
                    return ControlFlow::Break(PlanMismatch::UnsupportedShape);
                };
                if let Err(error) = self.add_relation(relation) {
                    return ControlFlow::Break(error);
                }
            }
            TableFactor::Derived {
                subquery,
                lateral,
                alias,
                ..
            } => {
                let kind = if *lateral {
                    QueryBlockKind::Lateral
                } else {
                    QueryBlockKind::DerivedTable
                };
                self.query_kinds
                    .insert(subquery.as_ref() as *const Query as usize, kind);
                if let Some(alias) = alias
                    && let Some(id) = self.current_block()
                {
                    self.derived_aliases.insert(
                        subquery.as_ref() as *const Query as usize,
                        (id, raw_name_part(&alias.name)),
                    );
                    self.blocks[id.0]
                        .statement_scope
                        .aliases
                        .push(raw_name_part(&alias.name));
                }
            }
            TableFactor::NestedJoin { .. }
            | TableFactor::Pivot { .. }
            | TableFactor::Unpivot { .. } => {}
            TableFactor::Table { args: Some(_), .. }
            | TableFactor::TableFunction { .. }
            | TableFactor::Function { .. }
            | TableFactor::JsonTable { .. }
            | TableFactor::XmlTable { .. } => {
                let parent = self.current_block();
                if let Err(error) = self.add_block(parent, QueryBlockKind::TableFunction) {
                    return ControlFlow::Break(error);
                }
            }
            _ => return ControlFlow::Break(PlanMismatch::UnsupportedShape),
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
        if self
            .order_alias_expressions
            .contains(&(expr as *const Expr))
        {
            return ControlFlow::Continue(());
        }
        let (query, kind) = match expr {
            Expr::Exists { subquery, .. } => {
                (Some(subquery.as_ref()), QueryBlockKind::ExistsSubquery)
            }
            Expr::InSubquery { subquery, .. } => {
                (Some(subquery.as_ref()), QueryBlockKind::InSubquery)
            }
            Expr::Subquery(query) => (Some(query.as_ref()), QueryBlockKind::ScalarSubquery),
            _ => (None, QueryBlockKind::ScalarSubquery),
        };
        if let Some(query) = query {
            self.query_kinds
                .insert(query as *const Query as usize, kind);
        }
        if let Expr::Function(function) = expr {
            if let Some(metric) = vector_distance_metric_expr(function) {
                self.metric_expressions.push(metric as *const Expr);
            }
            if let Some(model) = vector_embedding_model_expr(function) {
                self.model_expressions.push(model as *const Expr);
            }
        }
        if self
            .metric_expressions
            .iter()
            .any(|part| std::ptr::eq(*part, expr as *const Expr))
            || self
                .model_expressions
                .iter()
                .any(|part| std::ptr::eq(*part, expr as *const Expr))
        {
            return ControlFlow::Continue(());
        }
        let parts = match expr {
            Expr::Identifier(part) => std::slice::from_ref(part),
            Expr::CompoundIdentifier(parts) => parts.as_slice(),
            _ => return ControlFlow::Continue(()),
        };
        if parts.len() == 1
            && is_semantic_builtin_identifier(
                &parts[0],
                self.builtin_contexts.last().copied().unwrap_or_default(),
            )
        {
            return ControlFlow::Continue(());
        }
        if let Some(name) = raw_name_from_idents(parts, SyntacticRole::ValuePosition)
            && let Some(id) = self.current_block()
        {
            self.value_count += 1;
            if self.value_count > MAX_PLANNED_VALUES {
                return ControlFlow::Break(PlanMismatch::RelationPlanCapExceeded);
            }
            self.blocks[id.0].values.push(name);
        }
        ControlFlow::Continue(())
    }

    fn post_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
        if let Expr::Function(function) = expr {
            if let Some(metric) = vector_distance_metric_expr(function) {
                let ptr = metric as *const Expr;
                self.metric_expressions
                    .retain(|part| !std::ptr::eq(*part, ptr));
            }
            if let Some(model) = vector_embedding_model_expr(function) {
                let ptr = model as *const Expr;
                self.model_expressions
                    .retain(|part| !std::ptr::eq(*part, ptr));
            }
        }
        ControlFlow::Continue(())
    }
}

pub(super) fn build(query: &Query) -> Result<SemanticReadPlan, PlanMismatch> {
    let mut walker = BlockWalker::new();
    if let ControlFlow::Break(error) = query.visit(&mut walker) {
        return Err(error);
    }
    if walker.blocks.is_empty() {
        return Err(PlanMismatch::UnsupportedShape);
    }
    // A set query exposes the columns of its branches only when every branch
    // names the same explicit outputs. This deliberately refuses positional
    // or wildcard assumptions at a CTE/derived boundary.
    for index in (0..walker.blocks.len()).rev() {
        let branch_columns = walker
            .blocks
            .iter()
            .filter(|block| {
                block.parent == Some(QueryBlockId(index))
                    && block.kind == QueryBlockKind::SetOperationBranch
            })
            .map(|block| block.projected_columns.clone())
            .collect::<Vec<_>>();
        if let Some(first) = branch_columns.first()
            && !first.is_empty()
            && branch_columns.iter().all(|columns| columns == first)
        {
            walker.blocks[index].projected_columns = first.clone();
        }
    }
    let mut relations = Vec::new();
    let mut values = Vec::new();
    let mut seen_relations = HashSet::new();
    let mut seen_values = HashSet::new();
    for block in &mut walker.blocks {
        block
            .values
            .retain(|name| seen_values.insert((block.id, name.clone())));
        for relation in &block.relations {
            if seen_relations.insert(relation.clone()) {
                relations.push(relation.clone());
            }
        }
        for value in &block.values {
            if !values.contains(value) {
                values.push(value.clone());
            }
        }
    }
    for index in 0..walker.blocks.len() {
        let mut correlated = Vec::new();
        for value in &walker.blocks[index].values {
            let Some(first) = value.parts.first() else {
                continue;
            };
            if value.parts.len() < 2 {
                continue;
            }
            let key = normalized_part(first);
            if block_exposes(&walker.blocks[index], &key) {
                continue;
            }
            let mut ancestor = walker.blocks[index].parent;
            while let Some(id) = ancestor {
                if block_exposes(&walker.blocks[id.0], &key) {
                    correlated.push(value.clone());
                    break;
                }
                ancestor = walker.blocks[id.0].parent;
            }
        }
        walker.blocks[index].correlated_outer_refs = correlated;
    }
    let root_scope = walker.blocks[0].statement_scope.clone();
    Ok(SemanticReadPlan {
        relations,
        values,
        statement_scope: root_scope,
        blocks: walker.blocks,
    })
}

fn block_exposes(block: &QueryBlock, qualifier: &str) -> bool {
    block
        .statement_scope
        .aliases
        .iter()
        .any(|part| normalized_part(part) == qualifier)
        || block.statement_scope.relations.iter().any(|relation| {
            relation.alias.is_none()
                && relation
                    .name
                    .parts
                    .last()
                    .is_some_and(|part| normalized_part(part) == qualifier)
        })
}
