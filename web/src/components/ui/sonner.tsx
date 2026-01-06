import { Toaster as Sonner } from 'sonner'

type ToasterProps = React.ComponentProps<typeof Sonner>

function Toaster({ ...props }: ToasterProps) {
  return (
    <Sonner
      theme="dark"
      className="toaster group"
      toastOptions={{
        classNames: {
          toast:
            'group toast group-[.toaster]:bg-base-900 group-[.toaster]:text-foreground group-[.toaster]:border-base-700 group-[.toaster]:shadow-lg',
          description: 'group-[.toast]:text-muted-foreground',
          actionButton:
            'group-[.toast]:bg-primary group-[.toast]:text-primary-foreground',
          cancelButton:
            'group-[.toast]:bg-muted group-[.toast]:text-muted-foreground',
          success: 'group-[.toaster]:border-success/30 group-[.toaster]:text-success-muted',
          error: 'group-[.toaster]:bg-red-950 group-[.toaster]:border-red-500/40 group-[.toaster]:text-red-200',
        },
      }}
      {...props}
    />
  )
}

export { Toaster }
