"""Tests de RepoIngester usando un repo git real en tmp_path."""

import subprocess
from pathlib import Path

import pytest

from vibeaudit.ingester import RepoIngester


def make_git_repo(path):
    """Crea un repo git real con archivos de ejemplo y un commit."""
    (path / "app").mkdir(parents=True)
    (path / "app" / "main.py").write_text("print('hola')\n")
    (path / "package.json").write_text('{"name": "demo"}\n')
    (path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
    (path / "notes.txt").write_text("solo texto\n")
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True)
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=path, check=True)


class TestRepoIngester:
    def test_ingest_detecta_lenguajes_frameworks_e_iac(self, tmp_path):
        repo_dir = tmp_path / "src"
        repo_dir.mkdir()
        make_git_repo(repo_dir)

        metadata = RepoIngester(str(repo_dir)).ingest()

        assert metadata.name == "src"
        assert "Python" in metadata.languages
        assert "JavaScript" in metadata.languages
        assert metadata.iac_files == ["main.tf"]
        assert "notes.txt" not in metadata.iac_files

    def test_ingest_limpia_el_directorio_temporal(self, tmp_path):
        repo_dir = tmp_path / "src"
        repo_dir.mkdir()
        make_git_repo(repo_dir)

        ingester = RepoIngester(str(repo_dir))
        ingester.ingest()
        assert ingester.repo_path is None
        assert ingester._temp_dir is None

    def test_repo_inexistente_lanza_valueerror(self, tmp_path):
        with pytest.raises(ValueError):
            RepoIngester(str(tmp_path / "no-existe")).ingest()

    def test_context_manager_limpia_al_salir(self, tmp_path):
        repo_dir = tmp_path / "src"
        repo_dir.mkdir()
        make_git_repo(repo_dir)

        with RepoIngester(str(repo_dir)) as ingester:
            ingester.clone()
            assert ingester.repo_path is not None
            metadata = ingester.analyze()
            assert metadata.name == "src"

        assert ingester.repo_path is None

    def test_ingest_directo(self, tmp_path):
        repo_dir = tmp_path / "src"
        repo_dir.mkdir()
        make_git_repo(repo_dir)

        metadata = RepoIngester(str(repo_dir)).ingest()
        assert metadata.name == "src"
        assert metadata.languages

    def test_ingest_captura_rama_y_commit(self, tmp_path):
        repo_dir = tmp_path / "src"
        repo_dir.mkdir()
        make_git_repo(repo_dir)

        metadata = RepoIngester(str(repo_dir)).ingest()

        assert metadata.default_branch == "main" or metadata.default_branch == "master"
        assert metadata.commit_hash
        assert len(metadata.commit_hash) == 40

    def test_repository_url_conserva_la_original_en_clones_locales(self, tmp_path):
        repo_dir = tmp_path / "src"
        repo_dir.mkdir()
        make_git_repo(repo_dir)

        metadata = RepoIngester(str(repo_dir)).ingest()

        assert metadata.repository_url == str(repo_dir)


class TestRepoIngesterLocal:
    def test_local_path_sin_git_metadatos_parciales(self, tmp_path):
        local_dir = tmp_path / "mi-proyecto"
        local_dir.mkdir()
        (local_dir / "main.py").write_text("print('hola')\n")
        (local_dir / "notes.txt").write_text("solo texto\n")

        metadata = RepoIngester(local_path=local_dir).ingest()

        assert metadata.name == "mi-proyecto"
        assert "Python" in metadata.languages
        assert metadata.repository_url is None
        assert metadata.default_branch is None
        assert metadata.commit_hash is None

    def test_local_path_con_git_captura_rama_y_commit(self, tmp_path):
        local_dir = tmp_path / "repo-local"
        local_dir.mkdir()
        make_git_repo(local_dir)

        metadata = RepoIngester(local_path=local_dir).ingest()

        assert metadata.name == "repo-local"
        assert metadata.default_branch is not None
        assert metadata.commit_hash and len(metadata.commit_hash) == 40

    def test_local_path_inexistente_lanza_valueerror(self, tmp_path):
        with pytest.raises(ValueError):
            RepoIngester(local_path=tmp_path / "no-existe").ingest()

    def test_local_path_es_archivo_lanza_valueerror(self, tmp_path):
        archivo = tmp_path / "archivo.txt"
        archivo.write_text("contenido\n")

        with pytest.raises(ValueError):
            RepoIngester(local_path=archivo).ingest()

    def test_local_path_no_borra_el_directorio(self, tmp_path):
        local_dir = tmp_path / "mi-proyecto"
        local_dir.mkdir()
        (local_dir / "main.py").write_text("print('hola')\n")

        with RepoIngester(local_path=local_dir) as ingester:
            ingester.clone()
            assert ingester.repo_path == local_dir.resolve()
            ingester.analyze()

        assert local_dir.exists()
        assert (local_dir / "main.py").exists()

    def test_ambos_argumentos_lanza_valueerror(self):
        with pytest.raises(ValueError):
            RepoIngester(repo_url="https://github.com/x/y", local_path=Path("/tmp"))

    def test_ningun_argumento_lanza_valueerror(self):
        with pytest.raises(ValueError):
            RepoIngester()
