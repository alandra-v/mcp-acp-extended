/**
 * JSON view for policy configuration.
 *
 * Features:
 * - Editable textarea with monospace font
 * - "Add Rule from JSON" button with template
 * - Full policy JSON editing with save/discard
 * - Excludes HITL config from editing (managed separately)
 */

import { useState, useEffect, useCallback, useMemo } from 'react'
import { Save, RotateCcw, AlertTriangle, Plus } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog'
import { cn } from '@/lib/utils'
import type { PolicyResponse, PolicyFullUpdate, PolicyRuleCreate } from '@/types/api'

interface PolicyJsonViewProps {
  /** Current policy */
  policy: PolicyResponse
  /** Callback to save full policy */
  onSave: (policy: PolicyFullUpdate) => Promise<void>
  /** Callback to add a single rule */
  onAddRule: (rule: PolicyRuleCreate) => Promise<unknown>
  /** Whether a mutation is in progress */
  mutating: boolean
}

/** Rule JSON template for adding new rules */
const RULE_TEMPLATE: PolicyRuleCreate = {
  id: 'new-rule',
  description: 'Description of what this rule does',
  effect: 'deny',
  conditions: {
    tool_name: '*',
    path_pattern: '**/*',
  },
}

/** Convert policy response to editable format (without HITL) */
function policyToEditable(policy: PolicyResponse): Omit<PolicyFullUpdate, 'hitl'> {
  return {
    version: policy.version,
    default_action: policy.default_action,
    rules: policy.rules.map((rule) => ({
      id: rule.id || undefined,
      description: rule.description || undefined,
      effect: rule.effect,
      conditions: rule.conditions,
    })),
  }
}

/** Parse JSON and return error message if invalid */
function parseJsonSafe<T>(text: string): { data: T | null; error: string | null } {
  try {
    return { data: JSON.parse(text) as T, error: null }
  } catch (err) {
    return {
      data: null,
      error: err instanceof Error ? err.message : 'Invalid JSON',
    }
  }
}

export function PolicyJsonView({
  policy,
  onSave,
  onAddRule,
  mutating,
}: PolicyJsonViewProps): JSX.Element {
  // Original JSON for comparison (without HITL)
  const originalJson = useMemo(() => {
    return JSON.stringify(policyToEditable(policy), null, 2)
  }, [policy])

  const [jsonText, setJsonText] = useState(originalJson)
  const [parseError, setParseError] = useState<string | null>(null)
  const [addDialogOpen, setAddDialogOpen] = useState(false)
  const [addJsonText, setAddJsonText] = useState('')
  const [addParseError, setAddParseError] = useState<string | null>(null)

  // Reset when policy changes externally
  useEffect(() => {
    setJsonText(originalJson)
    setParseError(null)
  }, [originalJson])

  // Check if dirty
  const isDirty = jsonText !== originalJson

  // Validate JSON on change
  const handleChange = useCallback((e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const text = e.target.value
    setJsonText(text)
    const { error } = parseJsonSafe(text)
    setParseError(error)
  }, [])

  // Handle save
  const handleSave = useCallback(async () => {
    const { data: parsed, error } = parseJsonSafe<Omit<PolicyFullUpdate, 'hitl'>>(jsonText)
    if (!parsed) {
      setParseError(error)
      return
    }

    // Include original HITL config when saving
    await onSave({
      ...parsed,
      hitl: policy.hitl,
    })
  }, [jsonText, onSave, policy.hitl])

  // Handle cancel/reset
  const handleDiscard = useCallback(() => {
    setJsonText(originalJson)
    setParseError(null)
  }, [originalJson])

  // Open add dialog with template
  const handleAddClick = useCallback(() => {
    setAddJsonText(JSON.stringify(RULE_TEMPLATE, null, 2))
    setAddParseError(null)
    setAddDialogOpen(true)
  }, [])

  // Handle add JSON change
  const handleAddJsonChange = useCallback((e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const text = e.target.value
    setAddJsonText(text)
    const { error } = parseJsonSafe(text)
    setAddParseError(error)
  }, [])

  // Handle add submit
  const handleAddSubmit = useCallback(async () => {
    const { data: parsed } = parseJsonSafe<PolicyRuleCreate>(addJsonText)
    if (!parsed) return

    await onAddRule(parsed)
    setAddDialogOpen(false)
  }, [addJsonText, onAddRule])

  return (
    <div className="space-y-4">
      {/* Header with Add button */}
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          Edit full policy JSON (HITL config managed in Config section)
        </div>
        <Button size="sm" variant="outline" onClick={handleAddClick} disabled={mutating}>
          <Plus className="w-4 h-4 mr-2" />
          Add Rule from JSON
        </Button>
      </div>

      {/* Editor */}
      <div className="relative">
        <textarea
          value={jsonText}
          onChange={handleChange}
          className={cn(
            'w-full min-h-[400px] p-4 font-mono text-sm',
            'bg-base-950 border rounded-lg resize-y',
            'focus:outline-none focus:ring-2 focus:ring-primary/50',
            parseError
              ? 'border-destructive focus:ring-destructive/50'
              : 'border-base-700'
          )}
          spellCheck={false}
          disabled={mutating}
        />

        {/* Parse Error */}
        {parseError && (
          <div className="absolute bottom-4 left-4 right-4 bg-destructive/10 border border-destructive/30 rounded-md p-3 flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-destructive flex-shrink-0 mt-0.5" />
            <div className="text-sm text-destructive">
              <span className="font-medium">Invalid JSON: </span>
              <span>{parseError}</span>
            </div>
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          {isDirty ? (
            <span className="flex items-center gap-2">
              <span className="w-2 h-2 bg-yellow-500 rounded-full" />
              Unsaved changes
            </span>
          ) : (
            <span className="text-muted-foreground/50">No changes</span>
          )}
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleDiscard}
            disabled={!isDirty || mutating}
          >
            <RotateCcw className="w-4 h-4 mr-2" />
            Discard
          </Button>
          <Button
            size="sm"
            onClick={handleSave}
            disabled={!isDirty || !!parseError || mutating}
          >
            <Save className="w-4 h-4 mr-2" />
            {mutating ? 'Saving...' : 'Save Policy'}
          </Button>
        </div>
      </div>

      {/* Add Rule from JSON Dialog */}
      <Dialog open={addDialogOpen} onOpenChange={setAddDialogOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Add Rule from JSON</DialogTitle>
          </DialogHeader>

          <div className="py-4">
            <p className="text-sm text-muted-foreground mb-3">
              Edit the JSON template below and click Add to create a new rule.
            </p>
            <textarea
              value={addJsonText}
              onChange={handleAddJsonChange}
              className={cn(
                'w-full min-h-[250px] p-4 font-mono text-sm',
                'bg-base-900 border rounded-lg resize-y',
                'focus:outline-none focus:ring-2 focus:ring-primary/50',
                addParseError
                  ? 'border-destructive focus:ring-destructive/50'
                  : 'border-base-700'
              )}
              spellCheck={false}
              disabled={mutating}
            />

            {addParseError && (
              <div className="mt-2 flex items-start gap-2 text-sm text-destructive">
                <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                <span>{addParseError}</span>
              </div>
            )}
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setAddDialogOpen(false)}
              disabled={mutating}
            >
              Cancel
            </Button>
            <Button
              onClick={handleAddSubmit}
              disabled={!!addParseError || !addJsonText.trim() || mutating}
            >
              {mutating ? 'Adding...' : 'Add Rule'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
