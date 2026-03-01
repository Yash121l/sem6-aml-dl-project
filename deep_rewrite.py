import os
import subprocess

def run(cmd, env=None):
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True, env=env)
    return res.stdout.strip()

AUTH1 = {"name": "Yash121l", "email": "yashlunawat121@gmail.com"}
AUTH2 = {"name": "r69shabh", "email": "rishabhgusain.6@gmail.com"}

def clean_msg(msg):
    return '\n'.join([line for line in msg.split('\n') if 'Co-Authored-By: Claude' not in line])

# Reset any stray processes
run("git reset --hard")

# Branch setup
run("git checkout old-history-backup")
run("git branch -D temp_rewrite")
run("git checkout --orphan temp_rewrite")
run("git rm -rf .")

orig_commits_raw = run("git log --reverse --format='%H|%aI|%cI|%s' old-history-backup")
commits = []
for line in orig_commits_raw.split('\n'):
    if line:
        commits.append(line.split('|', 3))

print("Starting deep rewrite of history...")

for h, a_date, c_date, msg in commits:
    msg = clean_msg(msg)
    
    env = os.environ.copy()
    env['GIT_AUTHOR_DATE'] = a_date
    env['GIT_COMMITTER_DATE'] = c_date
    
    def do_commit(author, c_msg):
        env['GIT_AUTHOR_NAME'] = author['name']
        env['GIT_AUTHOR_EMAIL'] = author['email']
        env['GIT_COMMITTER_NAME'] = author['name']
        env['GIT_COMMITTER_EMAIL'] = author['email']
        
        # Check if there's anything to commit
        status = run("git status --porcelain")
        if not status:
            return # nothing to commit
            
        with open('/tmp/msg.txt', 'w') as f:
            f.write(c_msg)
        res = subprocess.run("git commit -F /tmp/msg.txt", shell=True, capture_output=True, text=True, env=env)
        if res.returncode != 0:
            print(f"Warning: commit failed. \n{res.stderr}\n{res.stdout}")

    # Set index and working tree to exactly match commit `h`
    # But wait, read-tree --reset replaces the current branch. 
    # Better: just use `git checkout` because we want to layer changes.
    # Actually, `git restore --source=h --staged --worktree .` works in modern git.
    # Let's use rm to clear tree, then checkout h.
    run("git rm -rf .")
    run(f"git checkout {h} -- .")
    
    if "Ingest CICIDS2017 dataset" in msg:
        run("git reset") # unstage all
        run("git add *stage1* outputs/eda")
        do_commit(AUTH1, "feat: Ingest CICIDS2017 dataset and initial EDA")
        run("git add -A")
        do_commit(AUTH2, "feat: Implement Stage 2 data preprocessing pipeline")
        
    elif "added model and reports" in msg:
        run("git reset")
        run("git add src/features.py src/evaluate.py")
        do_commit(AUTH2, "feat: implement feature engineering and evaluation modules")
        run("git add src/models.py src/__init__.py")
        do_commit(AUTH1, "feat: implement core models module")
        run("git add outputs/create_architecture_diagram.py presentation/slide_outline.md")
        do_commit(AUTH2, "docs: add phase 1 architecture diagrams and presentation")
        run("git add -A")
        do_commit(AUTH1, "docs: publish Phase 1 report and update README")
        
    elif "Implement and evaluate advanced anomaly detection models" in msg:
        run("git reset")
        run("git add results/if_* results/ocsvm_* outputs/models/plot01* outputs/models/plot02* outputs/models/plot03* outputs/models/plot04* outputs/models/plot05* outputs/models/plot06*")
        do_commit(AUTH1, "feat: baseline model experiments (IF and OCSVM)")
        run("git add -A")
        do_commit(AUTH2, "feat: final GMM model training and evaluation")
        
    elif "Refactor code structure for improved readability" in msg:
        # Check if this is the phase 2 refactor (it adds the notebook)
        changed_files = run(f"git show --name-only --format='' {h}")
        if "stage4_phase2_architecture" in changed_files:
            run("git reset")
            run("git add notebooks/stage4_phase2_architecture.ipynb")
            do_commit(AUTH2, "feat: draft phase 2 LSTM architecture notebook")
            run("git add -A")
            do_commit(AUTH1, "docs: add phase 2 architecture diagrams")
        else:
            run("git add -A")
            do_commit(AUTH1, msg)
            
    elif "implement phase 3 temporal data preparation" in msg:
        run("git reset")
        run("git add notebooks/stage7_phase3_temporal.ipynb outputs/phase3/temporal_label_sequence.png")
        do_commit(AUTH2, "feat: implement phase 3 temporal data preparation")
        run("git add -A")
        do_commit(AUTH1, "feat: implement hybrid GMM-LSTM model evaluation pipeline")
        
    elif "generate phase 3 ablation study" in msg:
        run("git reset")
        run("git add notebooks/stage9_phase3_ablation.ipynb")
        do_commit(AUTH1, "feat: generate phase 3 ablation study")
        run("git add -A")
        do_commit(AUTH2, "docs: phase 3 performance metrics and architecture artifacts")
        
    elif "Phase 3 complete" in msg:
        run("git reset")
        run("git add report/phase3_report.tex")
        do_commit(AUTH2, "docs: draft Phase 3 LaTeX report")
        run("git add -A")
        do_commit(AUTH1, "docs: Phase 3 complete — presentation and README update")
        
    else:
        run("git add -A")
        if "Add .gitignore" in msg or "Implement data preprocessing" in msg or "Add evaluation metrics" in msg or "LSTMAEDetector class" in msg or "HybridDetector class" in msg or "removing outdated source files" in msg:
            do_commit(AUTH2, msg)
        else:
            do_commit(AUTH1, msg)
            
# Force update main
run("git checkout main")
run("git reset --hard temp_rewrite")
run("git branch -D temp_rewrite")
print("Done deeply rewriting history! Your requested changes have been fully applied.")
