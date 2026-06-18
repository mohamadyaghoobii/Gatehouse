"use client";

import { useRef, useState } from "react";

type EditorProps = {
  value: string;
  onChange: (value: string) => void;
};

export function Editor({ value, onChange }: EditorProps) {
  const [drag, setDrag] = useState(false);
  const gutterRef = useRef<HTMLDivElement>(null);
  const lineCount = value.split("\n").length;
  const gutter = Array.from({ length: lineCount }, (_, index) => index + 1).join("\n");

  function onScroll(event: React.UIEvent<HTMLTextAreaElement>) {
    if (gutterRef.current) {
      gutterRef.current.scrollTop = event.currentTarget.scrollTop;
    }
  }

  async function onDrop(event: React.DragEvent) {
    event.preventDefault();
    setDrag(false);
    const file = event.dataTransfer.files?.[0];
    if (file) {
      onChange(await file.text());
    }
  }

  return (
    <div
      className={`editor-wrap editor ${drag ? "drag" : ""}`}
      onDragOver={(event) => {
        event.preventDefault();
        setDrag(true);
      }}
      onDragLeave={() => setDrag(false)}
      onDrop={onDrop}
    >
      <div className="gutter" ref={gutterRef}>
        {gutter}
      </div>
      <textarea
        value={value}
        spellCheck={false}
        onChange={(event) => onChange(event.target.value)}
        onScroll={onScroll}
        placeholder="Paste a GitHub Actions workflow, GitLab CI file, or Jenkinsfile — or drop a file here."
      />
    </div>
  );
}
